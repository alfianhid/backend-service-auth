// Package rbac Role Based Access Control
package rbac

import (
	models "bni/dgb/digi46/labs/auth-service-digi46/application/pkg/utl/models"

	"github.com/labstack/echo"
)

// New creates new RBAC service
func New() *Service {
	return &Service{}
}

// Service is RBAC application service
type Service struct{}

func checkBool(b bool) error {
	if b {
		return nil
	}
	return echo.ErrForbidden
}

// User returns user data stored in jwt token
func (s *Service) User(c echo.Context) *models.AuthUser {
	id := c.Get("id").(string)
	user := c.Get("username").(string)
	email := c.Get("email").(string)
	session_state := c.Get("session_state").(string)
	access_token := c.Get("access_token").(string)
	refresh_token := c.Get("refresh_token").(string)

	return &models.AuthUser{
		ID:           id,
		Username:     user,
		Email:        email,
		SessionState: session_state,
		AccessToken:  access_token,
		RefreshToken: refresh_token,
	}
}
