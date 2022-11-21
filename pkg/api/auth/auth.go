package auth

import (
	models "bni/dgb/digi46/labs/auth-service-digi46/application/pkg/utl/models"
	"net/http"

	"github.com/Nerzal/gocloak/v8"
	jwtGo "github.com/dgrijalva/jwt-go"

	"github.com/labstack/echo"
)

var (
	ErrInvalidCredentials = echo.NewHTTPError(http.StatusUnauthorized, "Username or password is not authorized")
)

func (a *Auth) Authenticate(c echo.Context, user, pass string) (*gocloak.JWT, error) {
	token, err := a.tg.GenerateToken(user, pass)
	if err != nil {
		return nil, models.ErrUnauthorized
	}

	tokenparse, err := a.tg.VerifyToken(token.AccessToken)
	claims := tokenparse.Claims.(jwtGo.MapClaims)
	if err != nil || !tokenparse.Valid {
		return nil, models.ErrUnauthorized
	}

	saveErr := a.tg.SaveSession(claims["jti"].(string), claims["session_state"].(string), token)
	if saveErr != nil {
		return nil, models.ErrUnauthorized
	}

	u, err := a.udb.FindByEmail(a.db, claims["email"].(string))
	u.UpdateLastLogin()
	if err := a.udb.Update(a.db, u); err != nil {
		return nil, err
	}

	return token, err
}

func (a *Auth) Refresh(c echo.Context, token string) (*gocloak.JWT, error) {
	tokenNew, err := a.tg.RefreshToken(token)
	if err != nil {
		return nil, models.ErrUnauthorized
	}

	tokenparse, err := a.tg.VerifyToken(tokenNew.AccessToken)
	claims := tokenparse.Claims.(jwtGo.MapClaims)
	if err != nil || !tokenparse.Valid {
		return nil, models.ErrUnauthorized
	}

	saveErr := a.tg.SaveSession(claims["jti"].(string), claims["session_state"].(string), tokenNew)
	if saveErr != nil {
		return nil, models.ErrUnauthorized
	}

	return tokenNew, err
}

func (a *Auth) Me(c echo.Context) (*models.AuthUser, error) {
	au := a.rbac.User(c)
	return au, nil
}

func (a *Auth) ChangePassword(c echo.Context, email, old_password, new_password string) (*models.Response, error) {
	u, err := a.udb.FindByEmail(a.db, email)
	if err != nil {
		return nil, err
	}

	matched := a.sec.HashMatchesPassword(u.Password, old_password)
	if !matched {
		return nil, models.ErrUnauthorized
	}

	token, err := a.tg.GetTokenAdmin()
	if err != nil {
		return nil, err
	}

	err = a.tg.SetUserPassword(token, u.UserID, new_password)
	if err != nil {
		return nil, err
	}

	u.ChangePassword(a.sec.Hash(new_password))
	if err := a.udb.Update(a.db, u); err != nil {
		return nil, err
	}

	return &models.Response{Status: 200, Message: true}, nil
}

func (a *Auth) Logout(c echo.Context) (*models.Response, error) {
	err := a.tg.Logout(c.Get("refresh_token").(string))
	if err != nil {
		return nil, err
	}

	return &models.Response{Status: 200, Message: true}, nil
}
