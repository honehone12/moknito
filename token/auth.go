package token

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type AuthTokenBundle struct {
	AccessToken     string `json:"access_token"`
	RefreshToken    string `json:"refresh_token"`
	BundleTokenType string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
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
	host    string
	hmacKey []byte
	rsaKey  *rsa.PrivateKey
}

func NewAuthTokenSigner() (*AuthTokenSigner, error) {
	// don't inject other than env
	// to prevent exposing sensitive info
	// just write within module for testing

	host := os.Getenv("AUTH_HOST")
	if len(host) == 0 {
		return nil, errors.New("could not find env for auth host")
	}

	var hmacKey []byte
	{
		encHKey := os.Getenv("AUTH_TOKEN_HMAC_KEY")
		if len(encHKey) != HMAC_KEY_ENV_LEN {
			return nil, errors.New("unexpected emac encoded key length")
		}
		hkey, err := base64.StdEncoding.DecodeString(encHKey)
		if err != nil {
			return nil, err
		}
		if len(hkey) != HMAC_KEY_LEN {
			return nil, errors.New("unexpected hmac key length")
		}
		hmacKey = hkey
	}

	var rsaKey *rsa.PrivateKey
	{
		encRKey := os.Getenv("AUTH_TOKEN_RSA_KEY")
		if len(encRKey) == 0 {
			return nil, errors.New("un expected encoded rsa key length")
		}
		b, err := base64.StdEncoding.DecodeString(encRKey)
		if err != nil {
			return nil, err
		}
		priv, err := jwt.ParseRSAPrivateKeyFromPEM(b)
		if err != nil {
			return nil, err
		}
		rsaKey = priv
	}

	return &AuthTokenSigner{host, hmacKey, rsaKey}, nil
}

type CreateAuthTokenParams struct {
	Method       jwt.SigningMethod
	TokenType    string
	AuthUuid     uuid.UUID
	UserUuid     uuid.UUID
	Ttl          time.Duration
	Applications []string
}

func (a *AuthTokenSigner) sign(t *jwt.Token, m jwt.SigningMethod) (string, error) {
	switch m {
	case jwt.SigningMethodHS256:
		return t.SignedString(a.hmacKey)
	case jwt.SigningMethodRS256:
		return t.SignedString(a.rsaKey)
	default:
		return "", errors.New("unsupported signature method")
	}
}

func (a *AuthTokenSigner) key(m jwt.SigningMethod) (any, error) {
	switch m {
	case jwt.SigningMethodHS256:
		return a.hmacKey, nil
	case jwt.SigningMethodRS256:
		return a.rsaKey, nil
	default:
		return nil, errors.New("key is not available for the signature method")
	}
}

func (a *AuthTokenSigner) CreateAuthToken(p CreateAuthTokenParams) (string, error) {
	if len(p.Applications) == 0 {
		p.Applications = []string{a.host}
	}
	now := time.Now()
	tkn := jwt.NewWithClaims(
		p.Method,
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

	return a.sign(tkn, p.Method)
}

type ParseParams struct {
	Raw          string
	Method       jwt.SigningMethod
	Applications []string
}

// (!) token id and subject is not checked at parsing (!)
func (a *AuthTokenSigner) Parse(p ParseParams) (*AutheClaims, error) {
	if len(p.Applications) == 0 {
		p.Applications = []string{a.host}
	}

	tkn, err := jwt.ParseWithClaims(
		p.Raw,
		&AutheClaims{},
		func(*jwt.Token) (any, error) {
			return a.key(p.Method)
		},
		jwt.WithAllAudiences(p.Applications...),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithIssuer(a.host),
		jwt.WithStrictDecoding(),
		jwt.WithValidMethods([]string{p.Method.Alg()}),
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
