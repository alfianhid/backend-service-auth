package auth

import (
	"bni/dgb/digi46/labs/auth-service-digi46/application/pkg/api/auth"
	"bni/dgb/digi46/labs/auth-service-digi46/application/pkg/utl/models"
	"time"

	"github.com/Nerzal/gocloak/v8"

	"github.com/labstack/echo"
)

// packageName is the name of the package
const packageName = "auth"

// LogService represents auth logging service
type LogService struct {
	auth.Service
	logger models.Logger
}

// New creates new auth logging service
func New(svc auth.Service, logger models.Logger) *LogService {
	return &LogService{
		Service: svc,
		logger:  logger,
	}
}

// Authenticate logging
func (ls *LogService) Authenticate(c echo.Context, user, password string) (resp *gocloak.JWT, err error) {
	defer func(begin time.Time) {
		ls.logger.Log(
			c,
			packageName, "Authenticate request", err,
			map[string]interface{}{
				"req":  user,
				"took": time.Since(begin),
			},
		)
	}(time.Now())
	return ls.Service.Authenticate(c, user, password)
}

// Refresh logging
func (ls *LogService) Refresh(c echo.Context, req string) (resp *gocloak.JWT, err error) {
	defer func(begin time.Time) {
		ls.logger.Log(
			c,
			packageName, "Refresh request", err,
			map[string]interface{}{
				"req":  req,
				"resp": resp,
				"took": time.Since(begin),
			},
		)
	}(time.Now())
	return ls.Service.Refresh(c, req)
}

// Me logging
func (ls *LogService) Me(c echo.Context) (resp *models.AuthUser, err error) {
	defer func(begin time.Time) {
		ls.logger.Log(
			c,
			packageName, "Me request", err,
			map[string]interface{}{
				"resp": resp,
				"took": time.Since(begin),
			},
		)
	}(time.Now())
	return ls.Service.Me(c)
}

func (ls *LogService) ChangePassword(c echo.Context, email, old_password, new_password string) (resp *models.Response, err error) {
	defer func(begin time.Time) {
		ls.logger.Log(
			c,
			packageName, "Change password request", err,
			map[string]interface{}{
				"resp": resp,
				"took": time.Since(begin),
			},
		)
	}(time.Now())
	return ls.Service.ChangePassword(c, email, old_password, new_password)
}

func (ls *LogService) Logout(c echo.Context) (resp *models.Response, err error) {
	defer func(begin time.Time) {
		ls.logger.Log(
			c,
			packageName, "Logout request", err,
			map[string]interface{}{
				"resp": resp,
				"took": time.Since(begin),
			},
		)
	}(time.Now())
	return ls.Service.Logout(c)
}