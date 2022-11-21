// Package store contains the components necessary for api services
// to interact with the database
package user

import (
	models "bni/dgb/digi46/labs/auth-service-digi46/application/pkg/utl/models"
	"fmt"
	"log"
	"net/http"

	"github.com/jinzhu/gorm"
	"github.com/labstack/echo"
)

var (
	ErrAlreadyExists  = echo.NewHTTPError(http.StatusBadRequest, "email already exists")
	ErrRecordNotFound = echo.NewHTTPError(http.StatusNotFound, "email not found")
)

type UserDBClient struct{}

func NewUserDBClient() *UserDBClient {
	return &UserDBClient{}
}

func (u *UserDBClient) FindByEmail(db *gorm.DB, email string) (*models.Users, error) {
	var user = new(models.Users)
	if err := db.Set("gorm:auto_preload", true).Where("email = ?", email).First(&user).Error; gorm.IsRecordNotFoundError(err) {
		return user, ErrRecordNotFound
	} else if err != nil {
		log.Panicln(fmt.Sprintf("db connection error %v", err))
		return user, err
	}
	return user, nil
}

func (u *UserDBClient) Update(db *gorm.DB, user *models.Users) error {
	return db.Save(user).Error
}
