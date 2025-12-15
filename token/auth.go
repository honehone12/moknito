package token

import (
	"encoding/base64"
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const AUTHENTICATED_COOKIE_KEY = "ae"
const AUTHENTICATED_TOKEN_VERSION = "0.0.1"

type AuthenticatedToken struct {
	MoknitoTokenVersion string `json:"version"`
	jwt.RegisteredClaims
}

type AuthTokenSigner struct {
	host string
	key  []byte
}

func NewAuthTokenSigner() (*AuthTokenSigner, error) {
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

	host := os.Getenv("AUTH_HOST")
	if len(host) == 0 {
		return nil, errors.New("could not find env for auth host")
	}

	return &AuthTokenSigner{host, key}, nil
}

func (a *AuthTokenSigner) CreateAuthenticatedToken(
	id,
	email string,
	ttl time.Duration,
) (string, error) {
	now := time.Now()
	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		AuthenticatedToken{
			MoknitoTokenVersion: AUTHENTICATED_TOKEN_VERSION,
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    a.host,
				Subject:   email,
				Audience:  []string{a.host},
				ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
				ID:        id,
			},
		},
	)
	signed, err := token.SignedString(a.key)
	if err != nil {
		return "", err
	}

	return signed, nil
}
