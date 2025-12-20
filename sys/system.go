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
	"github.com/redis/go-redis/v9"
)

const USER_REGISTRATION_REDIS_KEY = "USERREG"
const AUTHENTICATED_COOKIE_KEY = "ae"
const AUTHENTICATION_MAX_ERROR = 10
const AUTHENTICATION_ERROR_REDIS_KEY = "ERROR"
const CHALLENGE_REDIS_KEY = "CHALL"
const SESSION_KEY_LEN = 16
const SESSION_COOKIE_KEY = "ss"
const SESSION_REDIS_KEY = "SESS"
const SESSION_NONCE_MAX = 100

const SECURE_COOKIE = false // for local

type Sys interface {
	SessionSigner
	AuthenticationSigner
	AuthorizationSigner
	UserSys
	InfoSys
	AppSys
	io.Closer
}

type E struct {
	ValidationErr error
	SystemErr     error
}

type TtlParams struct {
	RegistrationTtl time.Duration
	SessionTtl      time.Duration
	TokenTtl        time.Duration
	CodeTtl         time.Duration
}

type EntRdsSys struct {
	ent   *ent.Client
	redis *redis.Client

	ttl TtlParams

	sessionSigner *token.SessionTokenSigner
	authSigner    *token.AuthTokenSigner
}

func NewEntRdsSys(
	ttl TtlParams,
	entOptions ...ent.Option,
) (*EntRdsSys, error) {
	// don't inject other than env
	// to prevent exposing sensitive info
	// just write within module for testing

	sessionSigner, err := token.NewSessionTokenSigner()
	if err != nil {
		return nil, err
	}

	authSigner, err := token.NewAuthTokenSigner()
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
		ttl,
		sessionSigner,
		authSigner,
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
