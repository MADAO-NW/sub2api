package repository

import (
	"context"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/redis/go-redis/v9"
)

// updateCacheKeyPrefix 隔离不同仓库与版本通道的在线更新缓存。
const updateCacheKeyPrefix = "update:latest:"

type updateCache struct {
	rdb *redis.Client
}

func NewUpdateCache(rdb *redis.Client) service.UpdateCache {
	return &updateCache{rdb: rdb}
}

func (c *updateCache) GetUpdateInfo(ctx context.Context, namespace string) (string, error) {
	return c.rdb.Get(ctx, updateCacheKeyPrefix+namespace).Result()
}

func (c *updateCache) SetUpdateInfo(ctx context.Context, namespace, data string, ttl time.Duration) error {
	return c.rdb.Set(ctx, updateCacheKeyPrefix+namespace, data, ttl).Err()
}
