package sys

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"moknito/res"
	"moknito/token"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

const SESSION_KEY_LEN = 16
const SESSION_COOKIE_KEY = "ss"
const SESSION_REDIS_KEY = "SESS"

func (s *EntRdsSys) SetSessionCookie() echo.MiddlewareFunc {
	return s.setSessionCookie
}

func (s *EntRdsSys) VerifySessionCookie() echo.MiddlewareFunc {
	return s.verifySessionCookie
}

func (s *EntRdsSys) setSessionCookie(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		c := ctx.Request().Context()
		cookie, err := ctx.Cookie(SESSION_COOKIE_KEY)
		if errors.Is(err, http.ErrNoCookie) {
			value, err := s.create(c)
			if err != nil {
				return err
			}
			if err := s.set(ctx, value); err != nil {
				return err
			}

			return next(ctx)
		} else if err != nil {
			return err
		}

		sessKey, ok, err := s.verify(c, cookie)
		if err != nil {
			return err
		}
		if !ok {
			value, err := s.create(c)
			if err != nil {
				return err
			}
			if err := s.set(ctx, value); err != nil {
				return err
			}

			return next(ctx)
		}

		value, err := s.incr(c, sessKey)
		if err != nil {
			return err
		}
		if err := s.set(ctx, value); err != nil {
			return err
		}

		return next(ctx)
	}
}

func (s *EntRdsSys) verifySessionCookie(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		c := ctx.Request().Context()
		cookie, err := ctx.Cookie(SESSION_COOKIE_KEY)
		if errors.Is(err, http.ErrNoCookie) {
			ctx.Logger().Warn("no session cookie")
			// here might have to be Unauthorized resonse code,
			// but i user Forbidden because i don't want to rerun
			// WWW-Authenticate header
			return res.Forbidden(ctx)
		} else if err != nil {
			return err
		}

		if len(cookie.Value) == 0 {
			ctx.Logger().Warn("empty session cookie value")
			return res.BadRequest(ctx)
		}

		sessKey, ok, err := s.verify(c, cookie)
		if err != nil {
			return err
		}
		if !ok {
			ctx.Logger().Warn("invalid session cookie")
			return res.BadRequest(ctx)
		}

		value, err := s.incr(c, sessKey)
		if err != nil {
			return err
		}
		if err := s.set(ctx, value); err != nil {
			return err
		}

		return next(ctx)
	}
}

func (s *EntRdsSys) verify(
	ctx context.Context,
	cookie *http.Cookie,
) ([]byte, bool, error) {
	dec, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, false, err
	}
	if len(dec) <= token.SIGNATURE_LEN {
		return nil, false, nil
	}

	sessKey := dec[token.SIGNATURE_LEN:]

	key := fmt.Sprintf("%s:%x", SESSION_REDIS_KEY, sessKey)
	nonce, err := s.redis.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}

	ok, err := s.sessionSigner.Verify(
		dec[:token.SIGNATURE_LEN],
		sessKey,
		nonce,
	)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, nil
	}

	return sessKey, true, nil
}

func (s *EntRdsSys) set(ctx echo.Context, value string) error {
	cookie := http.Cookie{
		Name:     SESSION_COOKIE_KEY,
		Value:    value,
		Path:     "/",
		MaxAge:   int(s.tokenTtl.Seconds()),
		Secure:   false, // for local
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	if err := cookie.Valid(); err != nil {
		return err
	}
	ctx.SetCookie(&cookie)

	return nil
}

func (s *EntRdsSys) create(ctx context.Context) (string, error) {
	sessKey := make([]byte, SESSION_KEY_LEN)
	if _, err := rand.Read(sessKey); err != nil {
		return "", err
	}

	key := fmt.Sprintf("%s:%x", SESSION_REDIS_KEY, sessKey)
	nonce := "0"
	if err := s.redis.SetEx(ctx, key, nonce, s.tokenTtl).Err(); err != nil {
		return "", err
	}

	return s.sessionSigner.SignedCookie(sessKey, nonce)
}

func (s *EntRdsSys) incr(ctx context.Context, sessKey []byte) (string, error) {
	key := fmt.Sprintf("%s:%x", SESSION_REDIS_KEY, sessKey)
	nonce, err := s.redis.Incr(ctx, key).Result()
	if err != nil {
		return "", err
	}
	if err := s.redis.Expire(ctx, key, s.tokenTtl).Err(); err != nil {
		return "", err
	}

	return s.sessionSigner.SignedCookie(sessKey, strconv.FormatInt(nonce, 10))
}
