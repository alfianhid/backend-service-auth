// Package transport contians HTTP service for authentication
package transport

import (
	"bni/dgb/digi46/labs/auth-service-digi46/application/pkg/api/auth"
	"net/http"

	"github.com/labstack/echo"
)

var (
	ErrUnknownPayload      = echo.NewHTTPError(http.StatusBadRequest, "payload is unknown")
	ErrPasswordsNotMaching = echo.NewHTTPError(http.StatusBadRequest, "passwords do not match")
)

// HTTP represents auth http service
type HTTP struct {
	svc auth.Service
}

// NewHTTP creates new auth http service
func NewHTTP(svc auth.Service, e *echo.Echo, mw echo.MiddlewareFunc) {
	h := HTTP{svc}

	ur := e.Group("/auth")

	ur.POST("/login", h.login)
	ur.GET("/refresh/:token", h.refresh)
	ur.GET("/me", h.me, mw)
	ur.POST("/change-password", h.changepassword, mw)
	ur.POST("/logout", h.logout, mw)
}

// credentials contains a username and password
type credentials struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

// login Logs in user by username and password
//
// usage: POST /login auth login
//
// responses:
//  200: loginResp
//  400: errMsg
//  401: errMsg
// 	403: err
//  404: errMsg
//  500: err
func (h *HTTP) login(c echo.Context) error {
	cred := new(credentials)
	if err := c.Bind(cred); err != nil {
		return err
	}
	r, err := h.svc.Authenticate(c, cred.Username, cred.Password)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, r)
}

// refresh Refreshes jwt token by checking if refresh token exists in db
//
// usage: GET /refresh/{token} auth refresh
//
// parameters:
// - name: token
//   in: path
//   description: refresh token
//   type: string
//   required: true
//
// responses:
//   "200":
//     "$ref": "#/responses/refreshResp"
//   "400":
//     "$ref": "#/responses/errMsg"
//   "401":
//     "$ref": "#/responses/err"
//   "500":
//     "$ref": "#/responses/err"
func (h *HTTP) refresh(c echo.Context) error {
	r, err := h.svc.Refresh(c, c.Param("token"))
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, r)
}

// me Gets user's info from session.
//
// usage: GET /me auth meReq
//
// responses:
//  200: userResp
//  500: err
func (h *HTTP) me(c echo.Context) error {
	user, err := h.svc.Me(c)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, user)
}

// changeReq is a used to serialize the request payload to a struct
type changeReq struct {
	Email              string `json:"email" validate:"required,email"`
	OldPassword        string `json:"old_password" validate:"required"`
	NewPassword        string `json:"new_password" validate:"required,min=8"`
	NewPasswordConfirm string `json:"new_password_confirm" validate:"required"`
}

// register Creates new user account
//
// usage: POST /v1/users users userCreate
//
// responses:
//  200: userResp
//  400: errMsg
//  401: err
//  403: errMsg
//  500: err
func (h *HTTP) changepassword(c echo.Context) error {
	r := new(changeReq)

	if err := c.Bind(r); err != nil {
		return err
	}

	if r.NewPassword != r.NewPasswordConfirm {
		return ErrPasswordsNotMaching
	}

	usr, err := h.svc.ChangePassword(c, r.Email, r.OldPassword, r.NewPassword)

	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, usr)
}

// register Creates new user account
//
// usage: POST /v1/users users userCreate
//
// responses:
//  200: userResp
//  400: errMsg
//  401: err
//  403: errMsg
//  500: err
func (h *HTTP) logout(c echo.Context) error {
	usr, err := h.svc.Logout(c)

	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, usr)
}
