package cache

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
)

type Cache struct {
    redis  *redis.Client
    prefix string
}

type CacheOptions struct {
    DefaultExpiration time.Duration
    CleanupInterval  time.Duration
}

func NewCache(redis *redis.Client, prefix string) *Cache {
    return &Cache{
        redis:  redis,
        prefix: prefix,
    }
}

func (c *Cache) Get(ctx context.Context, key string, dest interface{}) error {
    data, err := c.redis.Get(ctx, c.prefix+key).Bytes()
    if err != nil {
        if err == redis.Nil {
            return errors.Wrap(err, "cache miss")
        }
        return errors.Wrap(err, "failed to get from cache")
    }

    if err := json.Unmarshal(data, dest); err != nil {
        return errors.Wrap(err, "failed to unmarshal cached data")
    }
    return nil
}

func (c *Cache) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
    data, err := json.Marshal(value)
    if err != nil {
        return errors.Wrap(err, "failed to marshal data for cache")
    }

    if err := c.redis.Set(ctx, c.prefix+key, data, expiration).Err(); err != nil {
        return errors.Wrap(err, "failed to set cache")
    }
    return nil
}

func (c *Cache) Delete(ctx context.Context, key string) error {
    if err := c.redis.Del(ctx, c.prefix+key).Err(); err != nil {
        return errors.Wrap(err, "failed to delete from cache")
    }
    return nil
}

func (c *Cache) Clear(ctx context.Context) error {
    iter := c.redis.Scan(ctx, 0, c.prefix+"*", 0).Iterator()
    for iter.Next(ctx) {
        if err := c.redis.Del(ctx, iter.Val()).Err(); err != nil {
            return errors.Wrap(err, "failed to clear cache")
        }
    }
    return errors.Wrap(iter.Err(), "failed to iterate over cache keys")
}
