// Package jsonwebtoken contains logic for using JSON web tokens
package keycloaks

import (
	"bni/dgb/digi46/labs/auth-service-digi46/application/pkg/utl/config"
	models "bni/dgb/digi46/labs/auth-service-digi46/application/pkg/utl/models"
	"context"
	"time"

	"github.com/Nerzal/gocloak/v8"
	"github.com/go-redis/redis/v8"

	"io/ioutil"
	"net/http"
	"strings"

	jwtGo "github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
)

// Service provides a Json-Web-Token authentication implementation
type Service struct {
	server        string
	realm         string
	client_id     string
	client_secret string
	path_key      string
	user_admin    string
	pass_admin    string
	realm_admin   string
	client        *redis.Client
	client_cloak  gocloak.GoCloak
	ctx           context.Context
}

// New generates new JWT service necessery for auth middleware
func New(cfg *config.Keycloaks, client *redis.Client) *Service {
	return &Service{
		server:        cfg.Server,
		realm:         cfg.Realm,
		client_id:     cfg.ClientId,
		client_secret: cfg.ClientSecret,
		path_key:      cfg.PathKey,
		user_admin:    cfg.UserAdmin,
		pass_admin:    cfg.PassAdmin,
		realm_admin:   cfg.RealmAdmin,
		client:        client,
		client_cloak:  gocloak.NewClient(cfg.Server),
		ctx:           context.Background(),
	}
}

// MWFunc makes JWT implement the Middleware interface.
func (j *Service) MWFunc() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			token, err := j.ParseToken(c)
			if err != nil || !token.Valid {
				return c.NoContent(http.StatusUnauthorized)
			}

			claims := token.Claims.(jwtGo.MapClaims)

			c, err = j.IsJTISessionStateActive(claims, c)
			if err != nil {
				return c.NoContent(http.StatusUnauthorized)
			}

			return next(c)
		}
	}
}

// ParseToken parses token from Authorization header
func (j *Service) ParseToken(c echo.Context) (*jwtGo.Token, error) {
	bearer := c.Request().Header.Get("Authorization")
	if bearer == "" {
		return nil, models.ErrGeneric
	}
	partsBearer := strings.SplitN(bearer, " ", 2)
	if len(partsBearer) != 2 || partsBearer[0] != "Bearer" {
		return nil, models.ErrGeneric
	}

	return j.VerifyToken(partsBearer[1])
}

func (j *Service) VerifyToken(tokenraw string) (*jwtGo.Token, error) {
	keyData, err := ioutil.ReadFile(j.path_key)
	if err != nil {
		return nil, err
	}

	key, err := jwtGo.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return nil, err
	}

	parser := jwtGo.Parser{}
	token, parts, err := parser.ParseUnverified(tokenraw, jwtGo.MapClaims{})
	if err != nil {
		return token, err
	}
	var vErr error

	token.Signature = parts[2]
	if err = token.Method.Verify(strings.Join(parts[0:2], "."), token.Signature, key); err != nil {
		vErr = jwtGo.ErrSignatureInvalid
	}

	if vErr == nil {
		token.Valid = true
	}

	return token, vErr
}

func (j *Service) GenerateToken(user, pass string) (*gocloak.JWT, error) {
	token, err := j.client_cloak.Login(j.ctx, j.client_id, j.client_secret, j.realm, user, pass)

	return token, err
}

func (j *Service) RefreshToken(refresh string) (*gocloak.JWT, error) {
	token, err := j.client_cloak.RefreshToken(j.ctx, refresh, j.client_id, j.client_secret, j.realm)

	return token, err
}

func (j *Service) IsJTISessionStateActive(claims jwtGo.MapClaims, c echo.Context) (echo.Context, error) {
	accesstoken := j.client.Get(context.Background(), claims["jti"].(string)).Val()
	refreshtoken := j.client.Get(context.Background(), claims["session_state"].(string)).Val()
	if accesstoken != "" {
		c.Set("id", claims["jti"].(string))
		c.Set("username", claims["preferred_username"].(string))
		c.Set("email", claims["email"].(string))
		c.Set("session_state", claims["session_state"].(string))
		c.Set("access_token", accesstoken)
		c.Set("refresh_token", refreshtoken)
	} else if accesstoken == "" && refreshtoken != "" {
		tokencloak, err := j.RefreshToken(refreshtoken)
		if err != nil {
			return c, models.ErrUnauthorized
		}
		token, err := j.VerifyToken(tokencloak.AccessToken)
		if err != nil {
			return c, jwtGo.ErrSignatureInvalid
		}
		claims := token.Claims.(jwtGo.MapClaims)

		c.Set("id", claims["jti"].(string))
		c.Set("username", claims["preferred_username"].(string))
		c.Set("email", claims["email"].(string))
		c.Set("session_state", claims["session_state"].(string))
		c.Set("access_token", tokencloak.AccessToken)
		c.Set("refresh_token", tokencloak.RefreshToken)

		saveErr := j.SaveSession(claims["jti"].(string), claims["session_state"].(string), tokencloak)
		if saveErr != nil {
			return c, models.ErrUnauthorized
		}
	} else {
		return c, models.ErrUnauthorized
	}

	return c, nil
}

func (j *Service) SaveSession(idbearer, idrefresh string, token *gocloak.JWT) error {
	at := time.Now().Local().Add(time.Second * time.Duration(int64(token.ExpiresIn)))
	rt := time.Now().Local().Add(time.Second * time.Duration(int64(token.RefreshExpiresIn)))
	now := time.Now()
	errAccess := j.client.Set(context.Background(), idbearer, token.AccessToken, at.Sub(now)).Err()
	if errAccess != nil {
		return errAccess
	}
	errRefresh := j.client.Set(context.Background(), idrefresh, token.RefreshToken, rt.Sub(now)).Err()
	if errRefresh != nil {
		return errRefresh
	}
	return nil
}

func (j *Service) GetTokenAdmin() (*gocloak.JWT, error) {
	token, err := j.client_cloak.LoginAdmin(j.ctx, j.user_admin, j.pass_admin, j.realm_admin)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (j *Service) SetUserPassword(token *gocloak.JWT, UserID, password string) error {
	err := j.client_cloak.SetPassword(j.ctx, token.AccessToken, UserID, j.realm, password, false)
	if err != nil {
		return err
	}

	return nil
}

func (j *Service) Logout(refreshtoken string) error {
	err := j.client_cloak.Logout(j.ctx, j.client_id, j.client_secret, j.realm, refreshtoken)
	if err != nil {
		return err
	}

	return nil
}
