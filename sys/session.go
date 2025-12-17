package sys

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"moknito/token"
	"net/http"
	"strconv"

	"github.com/redis/go-redis/v9"
)

const SESSION_KEY_LEN = 16
const SESSION_COOKIE_KEY = "ss"
const SESSION_REDIS_KEY = "SESS"

// (!) return verification error, system error (!)
func (s *EntRdsSys) VerifySession(
	ctx context.Context,
	cookie *http.Cookie,
) (*http.Cookie, error, error) {
	dec, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, nil, err
	}
	if len(dec) != token.SIGNATURE_LEN+SESSION_KEY_LEN {
		return nil, errors.New("invalid decoded session length"), nil
	}

	sessKey := dec[token.SIGNATURE_LEN:]

	key := fmt.Sprintf("%s:%x", SESSION_REDIS_KEY, sessKey)
	nonce, err := s.redis.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return nil, err, nil
	} else if err != nil {
		return nil, nil, err
	}

	ok, err := s.sessionSigner.Verify(
		dec[:token.SIGNATURE_LEN],
		sessKey,
		nonce,
	)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, errors.New("wrong session signature"), nil
	}

	value, err := s.incrSession(ctx, sessKey)
	if err != nil {
		return nil, nil, err
	}
	c, err := s.createSessionCookie(value)
	if err != nil {
		return nil, nil, err
	}

	return c, nil, nil
}

func (s *EntRdsSys) CreateSession(ctx context.Context) (*http.Cookie, error) {
	value, err := s.createSession(ctx)
	if err != nil {
		return nil, err
	}
	return s.createSessionCookie(value)
}

func (s *EntRdsSys) IncrSession(
	ctx context.Context,
	sessKey []byte,
) (*http.Cookie, error) {
	value, err := s.incrSession(ctx, sessKey)
	if err != nil {
		return nil, err
	}
	return s.createSessionCookie(value)
}

func (s *EntRdsSys) createSession(ctx context.Context) (string, error) {
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

func (s *EntRdsSys) incrSession(ctx context.Context, sessKey []byte) (string, error) {
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

func (s *EntRdsSys) createSessionCookie(value string) (*http.Cookie, error) {
	cookie := &http.Cookie{
		Name:     SESSION_COOKIE_KEY,
		Value:    value,
		Path:     "/",
		MaxAge:   int(s.tokenTtl.Seconds()),
		Secure:   false, // for local
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	if err := cookie.Valid(); err != nil {
		return nil, err
	}

	return cookie, nil
}
