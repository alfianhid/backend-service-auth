package redis

import (
	"bni/dgb/digi46/labs/auth-service-digi46/application/pkg/utl/config"
	"context"

	"github.com/go-redis/redis/v8"
)

func Initialize(redisConfig *config.Redis) *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr:     redisConfig.Server,
		Password: redisConfig.Password,
	})
	_, err := client.Ping(context.Background()).Result()
	if err != nil {
		panic(err)
	}
	return client
}
