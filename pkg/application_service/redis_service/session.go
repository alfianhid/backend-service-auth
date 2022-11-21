package redis_service

import (
	"context"
	"github.com/Nerzal/gocloak/v8"
	"github.com/go-redis/redis/v8"
	"time"
)

type UserSession struct{}

func NewUserSession() *UserSession {
	return &UserSession{}
}

func (u *UserSession) SaveSession(client *redis.Client, idbearer, idrefresh string, token *gocloak.JWT) error {
	at := time.Now().Local().Add(time.Second * time.Duration(int64(token.ExpiresIn)))
	rt := time.Now().Local().Add(time.Second * time.Duration(int64(token.RefreshExpiresIn)))
	now := time.Now()
	errAccess := client.Set(context.Background(),idbearer, token.AccessToken, at.Sub(now)).Err()
	if errAccess != nil {
		return errAccess
	}
	errRefresh := client.Set(context.Background(), idrefresh, token.RefreshToken, rt.Sub(now)).Err()
	if errRefresh != nil {
		return errRefresh
	}
	return nil
}




