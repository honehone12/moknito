package token

import (
	"encoding/base64"
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AuthenticatedToken struct {
	jwt.RegisteredClaims
}

type tokenSigner struct {
	host string
	key  []byte
}

func NewAuthTokenSigner() (*tokenSigner, error) {
	// don't inject other than env
	// to prevent exposing sensitive info
	// just write within module for testing

	encKey := os.Getenv("AUTH_TOKEN_KEY")
	if len(encKey) != SIGNATURE_KEY_ENV_LEN {
		return nil, errors.New("unexpected auth token signature key length")
	}
	key, err := base64.StdEncoding.DecodeString(encKey)
	if err != nil {
		return nil, err
	}
	if len(key) != SIGNATURE_KEY_LEN {
		return nil, errors.New("unexpected signature key length")
	}

	host := os.Getenv("HOST")
	if len(host) == 0 {
		return nil, errors.New("could not find env for host")
	}

	return &tokenSigner{host, key}, nil
}

func (s *tokenSigner) CreateAuthenticatedToken(
	id,
	email string,
	ttl time.Duration,
) (string, error) {
	now := time.Now()
	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		AuthenticatedToken{
			jwt.RegisteredClaims{
				Issuer:    s.host,
				Subject:   email,
				Audience:  []string{s.host},
				ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
				ID:        id,
			},
		},
	)
	signed, err := token.SignedString(s.key)
	if err != nil {
		return "", err
	}

	return signed, nil
}
