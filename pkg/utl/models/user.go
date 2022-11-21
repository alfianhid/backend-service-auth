package models

import "time"

type AuthUser struct {
	ID           string
	Username     string
	Email        string
	SessionState string
	AccessToken  string
	RefreshToken string
}

type Users struct {
	Base
	UserID        string `json:"user_id"`
	Email         string `json:"email"`
	Password      string `json:"password"`
	UrlImgProfile string `json:"url_image_profile"`

	LastLogin          time.Time `json:"last_login,omitempty" gorm:"default:CURRENT_TIMESTAMP"`
	LastPasswordChange time.Time `json:"last_password_change,omitempty" gorm:"default:CURRENT_TIMESTAMP"`
}

func (u *Users) ChangePassword(hash string) {
	u.Password = hash
	u.LastPasswordChange = time.Now()
}

func (u *Users) UpdateLastLogin() {
	u.LastLogin = time.Now()
}
