package queueprovider

import (
	"context"
	"fmt"

	redis "github.com/redis/go-redis/v9"

	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/queue"
	queueMemory "github.com/m-sec-org/d-eyes/server/internal/queue/memory"
	queueRedis "github.com/m-sec-org/d-eyes/server/internal/queue/redis"
)

func New(ctx context.Context, cfg config.Config) (queue.Queue, error) {
	if cfg.Redis.Enabled {
		client := redis.NewClient(&redis.Options{
			Addr:         cfg.Redis.Addr,
			Password:     cfg.Redis.Password,
			DB:           cfg.Redis.DB,
			DialTimeout:  cfg.Redis.DialTimeout,
			ReadTimeout:  cfg.Redis.ReadTimeout,
			WriteTimeout: cfg.Redis.WriteTimeout,
		})
		if err := client.Ping(ctx).Err(); err != nil {
			return nil, fmt.Errorf("connect redis: %w", err)
		}
		queueKey := cfg.Redis.QueueKey
		if queueKey == "" {
			queueKey = "d-eyes:task-queue"
		}
		return queueRedis.New(client, queueKey), nil
	}
	return queueMemory.New(), nil
}
