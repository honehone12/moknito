package token

import (
	"encoding/base64"
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const TOKEN_TYPE_AUTHENTICATION = "authentication"
const TOKEN_TYPE_AUTHORIZATION = "authorization"
const TOKEN_TYPE_REFRESH = "refresh"
const BUNDLE_TOKEN_TYPE_BEARER = "bearer"
const AUTHENTICATED_TOKEN_VERSION = "0.0.1"

type AuthTokenBundle struct {
	AccessToken     string `json:"access_token"`
	RefreshToken    string `json:"refresh_token"`
	BundleTokenType string `json:"token_type"`
	ExpiresIn       int64  `json:"expire_in"`
}

type AutheClaims struct {
	Version string `json:"version"`
	Type    string `json:"type"`
	jwt.RegisteredClaims
}

func (a *AutheClaims) Validate() error {
	switch a.Version {
	case AUTHENTICATED_TOKEN_VERSION:
		switch a.Type {
		case TOKEN_TYPE_AUTHENTICATION:
		case TOKEN_TYPE_AUTHORIZATION:
		case TOKEN_TYPE_REFRESH:
		default:
			return errors.New("unexpected token type")
		}
	default:
		return errors.New("unexpected token version")
	}
	return nil
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

type CreateAuthTokenParams struct {
	TokenType    string
	AuthUuid     uuid.UUID
	UserUuid     uuid.UUID
	Ttl          time.Duration
	Applications []string
}

func (a *AuthTokenSigner) CreateAuthToken(p CreateAuthTokenParams) (string, error) {
	if len(p.Applications) == 0 {
		p.Applications = []string{a.host}
	}
	now := time.Now()
	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		AutheClaims{
			Version: AUTHENTICATED_TOKEN_VERSION,
			Type:    p.TokenType,
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    a.host,
				Subject:   p.UserUuid.String(),
				Audience:  p.Applications,
				ExpiresAt: jwt.NewNumericDate(now.Add(p.Ttl)),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
				ID:        p.AuthUuid.String(),
			},
		},
	)
	signed, err := token.SignedString(a.key)
	if err != nil {
		return "", err
	}

	return signed, nil
}

// (!) token id and subject is not checked at parsing (!)
func (a *AuthTokenSigner) Parse(
	raw string,
	applications ...string,
) (*AutheClaims, error) {
	if len(applications) == 0 {
		applications = []string{a.host}
	}
	tkn, err := jwt.ParseWithClaims(
		raw,
		&AutheClaims{},
		func(*jwt.Token) (any, error) {
			return a.key, nil
		},
		jwt.WithAllAudiences(applications...),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithIssuer(a.host),
		jwt.WithStrictDecoding(),
		jwt.WithValidMethods([]string{"HS256"}),
	)
	if err != nil {
		return nil, err
	}
	if !tkn.Valid {
		return nil, errors.New("token is invalid")
	}

	c, ok := tkn.Claims.(*AutheClaims)
	if !ok {
		return nil, errors.New("failed to cast claims to authclaims")
	}

	return c, nil
}
