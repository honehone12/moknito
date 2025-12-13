package sys

import (
	"context"
	"errors"
	"io"
	"moknito/ent"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/redis/go-redis/v9"
)

type Sys interface {
	UserSys
	io.Closer
}

type EntRdsSys struct {
	ent   *ent.Client
	redis *redis.Client
}

func NewEntRdsSys(entOptions ...ent.Option) (*EntRdsSys, error) {
	// don't inject other than env
	// to prevent exposing sensitive info
	// just write within module for testing

	mysqlUri := os.Getenv("MYSQL_URI")
	if len(mysqlUri) == 0 {
		return nil, errors.New("could not find env for mysql uri")
	}
	redisHost := os.Getenv("REDIS_HOST")
	if len(redisHost) == 0 {
		return nil, errors.New("could not find env for redis host")
	}
	redisPw := os.Getenv("REDIS_PW")
	if len(redisPw) == 0 {
		return nil, errors.New("could not find env for redis pw")
	}

	ent, err := ent.Open(
		"mysql",
		mysqlUri,
		entOptions...,
	)
	if err != nil {
		return nil, err
	}

	redis := redis.NewClient(&redis.Options{
		Addr:     redisHost,
		Password: redisPw,
	})
	if err := redis.Ping(context.Background()).Err(); err != nil {
		return nil, err
	}

	return &EntRdsSys{ent, redis}, nil
}

func (s *EntRdsSys) Close() error {
	return s.ent.Close()
}

func (s *EntRdsSys) Ent() *ent.Client {
	return s.ent
}

func (s *EntRdsSys) Redis() *redis.Client {
	return s.redis
}
