package auth

import (
	"bni/dgb/digi46/labs/auth-service-digi46/application/pkg/application_service/data_service/user"
	models "bni/dgb/digi46/labs/auth-service-digi46/application/pkg/utl/models"

	"github.com/Nerzal/gocloak/v8"
	jwtGo "github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	"github.com/labstack/echo"
)

type Service interface {
	Authenticate(echo.Context, string, string) (*gocloak.JWT, error)
	Refresh(echo.Context, string) (*gocloak.JWT, error)
	Me(echo.Context) (*models.AuthUser, error)
	ChangePassword(echo.Context, string, string, string) (*models.Response, error)
	Logout(echo.Context) (*models.Response, error)
}

type TokenGenerator interface {
	GenerateToken(string, string) (*gocloak.JWT, error)
	RefreshToken(string) (*gocloak.JWT, error)
	VerifyToken(string) (*jwtGo.Token, error)
	SaveSession(string, string, *gocloak.JWT) error
	SetUserPassword(*gocloak.JWT, string, string) error
	GetTokenAdmin() (*gocloak.JWT, error)
	Logout(string) error
}

type DBClientInterface interface {
	FindByEmail(*gorm.DB, string) (*models.Users, error)
	Update(*gorm.DB, *models.Users) error
}

// Securer represents security interface
type Securer interface {
	HashMatchesPassword(string, string) bool
	Hash(string) string
	Password(string, ...string) bool
}

type RBAC interface {
	User(echo.Context) *models.AuthUser
}

// Auth represents auth application service
type Auth struct {
	tg   TokenGenerator
	rbac RBAC
	db   *gorm.DB
	udb  DBClientInterface
	sec  Securer
}

// New creates new iam service
func New(db *gorm.DB, udb DBClientInterface, sec Securer, rbac RBAC, j TokenGenerator) *Auth {
	return &Auth{
		sec:  sec,
		db:   db,
		udb:  udb,
		tg:   j,
		rbac: rbac,
	}
}

// Initialize initializes auth application service
func Initialize(db *gorm.DB, sec Securer, rbac RBAC, j TokenGenerator) *Auth {
	return New(db, user.NewUserDBClient(), sec, rbac, j)
}
