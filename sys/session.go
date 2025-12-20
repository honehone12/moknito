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

type SessionSigner interface {
	CreateSession(ctx context.Context) (*http.Cookie, error)
	IncrSession(
		ctx context.Context,
		sessKey []byte,
	) (*http.Cookie, error)
	VerifySession(
		ctx context.Context,
		cookie *http.Cookie,
	) *VerifySessionResult
}

type VerifySessionResult struct {
	SessionKey []byte
	E
}

func (s *EntRdsSys) VerifySession(
	ctx context.Context,
	cookie *http.Cookie,
) *VerifySessionResult {
	r := &VerifySessionResult{}

	dec, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		r.ValidationErr = err
		return r
	}
	if len(dec) != token.SIGNATURE_LEN+SESSION_KEY_LEN {
		r.ValidationErr = errors.New("invalid decoded session length")
		return r
	}

	sessKey := dec[token.SIGNATURE_LEN:]

	key := fmt.Sprintf("%s:%x", SESSION_REDIS_KEY, sessKey)
	nonce, err := s.redis.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		r.ValidationErr = errors.New("session key not found")
		return r
	} else if err != nil {
		r.SystemErr = err
		return r
	}

	ok, err := s.sessionSigner.Verify(
		dec[:token.SIGNATURE_LEN],
		sessKey,
		nonce,
	)
	if err != nil {
		r.SystemErr = err
		return r
	}
	if !ok {
		r.ValidationErr = errors.New("wrong session signature")
		return r
	}

	r.SessionKey = sessKey
	return r
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
	if err := s.redis.SetEx(ctx, key, nonce, s.ttl.SessionTtl).Err(); err != nil {
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
	if nonce >= SESSION_NONCE_MAX {
		return "", errors.New("session nonce count is over normal behavior")
	}

	if err := s.redis.Expire(ctx, key, s.ttl.SessionTtl).Err(); err != nil {
		return "", err
	}

	return s.sessionSigner.SignedCookie(sessKey, strconv.FormatInt(nonce, 10))
}

func (s *EntRdsSys) createSessionCookie(value string) (*http.Cookie, error) {
	cookie := &http.Cookie{
		Name:     SESSION_COOKIE_KEY,
		Value:    value,
		Path:     "/",
		MaxAge:   int(s.ttl.SessionTtl.Milliseconds() / 1000),
		Secure:   SECURE_COOKIE,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	if err := cookie.Valid(); err != nil {
		return nil, err
	}

	return cookie, nil
}
