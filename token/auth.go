package token

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"moknito/binid"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AuthTokenBundle struct {
	AccessToken     string `json:"access_token"`
	RefreshToken    string `json:"refresh_token"`
	BundleTokenType string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
}

type AuthClaims struct {
	Version string `json:"version"`
	Type    string `json:"type"`
	jwt.RegisteredClaims
}

func (a *AuthClaims) Validate() error {
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
	host       string
	hmacKey    []byte
	rsaPrivKey *rsa.PrivateKey
	rsaPubKey  *rsa.PublicKey
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

	var rsaPrivKey *rsa.PrivateKey
	{
		encRKey := os.Getenv("AUTH_TOKEN_RSA_PRIV_KEY")
		if len(encRKey) == 0 {
			return nil, errors.New("unexpected encoded rsa key length")
		}
		b, err := base64.StdEncoding.DecodeString(encRKey)
		if err != nil {
			return nil, err
		}
		priv, err := jwt.ParseRSAPrivateKeyFromPEM(b)
		if err != nil {
			return nil, err
		}
		rsaPrivKey = priv
	}
	var rsaPubKey *rsa.PublicKey
	{
		encRKey := os.Getenv("AUTH_TOKEN_RSA_PUB_KEY")
		if len(encRKey) == 0 {
			return nil, errors.New("unexpected encoded rsa key length")
		}
		b, err := base64.StdEncoding.DecodeString(encRKey)
		if err != nil {
			return nil, err
		}
		pub, err := jwt.ParseRSAPublicKeyFromPEM(b)
		if err != nil {
			return nil, err
		}
		rsaPubKey = pub
	}

	return &AuthTokenSigner{
		host,
		hmacKey,
		rsaPrivKey,
		rsaPubKey,
	}, nil
}

type CreateAuthTokenParams struct {
	Method       jwt.SigningMethod
	TokenType    string
	AuthId       binid.BinId
	UserId       binid.BinId
	Ttl          time.Duration
	Applications []string
}

func (a *AuthTokenSigner) sign(t *jwt.Token, m jwt.SigningMethod) (string, error) {
	switch m {
	case jwt.SigningMethodHS256:
		return t.SignedString(a.hmacKey)
	case jwt.SigningMethodRS256:
		return t.SignedString(a.rsaPrivKey)
	default:
		return "", errors.New("unsupported signature method")
	}
}

func (a *AuthTokenSigner) verificationKey(m jwt.SigningMethod) (any, error) {
	switch m {
	case jwt.SigningMethodHS256:
		return a.hmacKey, nil
	case jwt.SigningMethodRS256:
		return a.rsaPubKey, nil
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
		AuthClaims{
			Version: AUTHENTICATED_TOKEN_VERSION,
			Type:    p.TokenType,
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    a.host,
				Subject:   p.UserId.String(),
				Audience:  p.Applications,
				ExpiresAt: jwt.NewNumericDate(now.Add(p.Ttl)),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
				ID:        p.AuthId.String(),
			},
		},
	)

	return a.sign(tkn, p.Method)
}

type ParseParams struct {
	TokenType    string
	Raw          string
	Method       jwt.SigningMethod
	Applications []string
}

// (!) token id and subject is not checked at parsing (!)
func (a *AuthTokenSigner) Parse(p ParseParams) (*AuthClaims, error) {
	if len(p.Applications) == 0 {
		p.Applications = []string{a.host}
	}

	tkn, err := jwt.ParseWithClaims(
		p.Raw,
		&AuthClaims{},
		func(*jwt.Token) (any, error) {
			return a.verificationKey(p.Method)
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

	c, ok := tkn.Claims.(*AuthClaims)
	if !ok {
		return nil, errors.New("failed to cast claims to authclaims")
	}

	if c.Type != p.TokenType {
		return nil, errors.New("wrong token type")
	}

	return c, nil
}
