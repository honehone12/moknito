package sys

import (
	"context"
	"errors"
	"io"
	"moknito/ent"
	"moknito/token"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

type Sys interface {
	SetSessionCookie() echo.MiddlewareFunc
	VerifySessionCookie() echo.MiddlewareFunc

	UserSys
	io.Closer
}

type EntRdsSys struct {
	ent   *ent.Client
	redis *redis.Client

	tokenTtl      time.Duration
	sessionSigner *token.SessionTokenSigner
}

func NewEntRdsSys(
	tokenTtl time.Duration,
	entOptions ...ent.Option,
) (*EntRdsSys, error) {
	// don't inject other than env
	// to prevent exposing sensitive info
	// just write within module for testing

	sessionSigner, err := token.NewSessionTokenSigner()
	if err != nil {
		return nil, err
	}

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

	return &EntRdsSys{
		ent,
		redis,
		tokenTtl,
		sessionSigner,
	}, nil
}

func (s *EntRdsSys) Close() error {
	return s.ent.Close()
}

func (*EntRdsSys) rollback(tx *ent.Tx, original error) error {
	if err := tx.Rollback(); err != nil {
		return errors.Join(original, err)
	}

	return original
}
