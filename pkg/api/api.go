package api

import (
	"bni/dgb/digi46/labs/auth-service-digi46/application/pkg/utl/datastore"
	redisStore "bni/dgb/digi46/labs/auth-service-digi46/application/pkg/utl/redis"
	"bni/dgb/digi46/labs/auth-service-digi46/application/pkg/utl/secure"
	"crypto/sha1"

	"github.com/go-redis/redis/v8"
	"github.com/jinzhu/gorm"
	"github.com/labstack/echo"

	// pkg/api
	"bni/dgb/digi46/labs/auth-service-digi46/application/pkg/api/auth"
	al "bni/dgb/digi46/labs/auth-service-digi46/application/pkg/api/auth/logging"
	at "bni/dgb/digi46/labs/auth-service-digi46/application/pkg/api/auth/transport"

	// pkg/utl
	"bni/dgb/digi46/labs/auth-service-digi46/application/pkg/utl/config"
	keycloakService "bni/dgb/digi46/labs/auth-service-digi46/application/pkg/utl/middleware/keycloaks"
	rbacService "bni/dgb/digi46/labs/auth-service-digi46/application/pkg/utl/rbac"
	"bni/dgb/digi46/labs/auth-service-digi46/application/pkg/utl/server"
	"bni/dgb/digi46/labs/auth-service-digi46/application/pkg/utl/zlog"
)

// newServices initializes new services for API
func newServices(cfg *config.Configuration, client *redis.Client) (sec *secure.Service, rbac *rbacService.Service, jwt *keycloakService.Service, log *zlog.Log, e *echo.Echo) {
	sec = secure.New(cfg.App.MinPasswordStr, sha1.New())
	rbac = rbacService.New()
	jwt = keycloakService.New(cfg.Keycloaks, client)
	log = zlog.New()
	e = server.New()

	return sec, rbac, jwt, log, e
}

// initializeControllers initializes new HTTP services for each controller
func initializeControllers(db *gorm.DB, sec *secure.Service, rbac *rbacService.Service, jwt *keycloakService.Service, log *zlog.Log, e *echo.Echo) {
	at.NewHTTP(al.New(auth.Initialize(db, sec, rbac, jwt), log), e, jwt.MWFunc())
}

// startServer starts HTTP server with correct config & initialized services
func startServer(e *echo.Echo, cfg *config.Configuration) {
	server.Start(e, &server.Config{
		Port:                cfg.Server.Port,
		ReadTimeoutSeconds:  cfg.Server.ReadTimeout,
		WriteTimeoutSeconds: cfg.Server.WriteTimeout,
		Debug:               cfg.Server.Debug,
	})
}

// Start starts the API service
func Start(cfg *config.Configuration) error {
	client := redisStore.Initialize(cfg.Redis)
	db, err := datastore.NewMySQLGormDb(cfg.DB)
	if err != nil {
		return err
	}
	sec, rbac, jwt, log, e := newServices(cfg, client)

	initializeControllers(db, sec, rbac, jwt, log, e)

	e.Static("/swaggerui", cfg.App.SwaggerUIPath)

	startServer(e, cfg)

	return nil
}
