package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"moknito/binid"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var _ jwt.ClaimsValidator = &AuthClaims{}

func newTestKey(t *testing.T) (hmacKey string, rsaPrivKey string, rsaPubKey string) {
	t.Helper()
	hkey := make([]byte, HMAC_KEY_LEN)
	if _, err := rand.Read(hkey); err != nil {
		t.Fatalf("failed to generate hmac key: %v", err)
	}
	hmacKey = base64.StdEncoding.EncodeToString(hkey)

	pkey, err := rsa.GenerateKey(rand.Reader, RSA_PRIV_KEY_LEN)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}
	pkeyBytes := x509.MarshalPKCS1PrivateKey(pkey)
	pkeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: pkeyBytes,
	})
	rsaPrivKey = base64.StdEncoding.EncodeToString(pkeyPem)

	pubkeyBytes, err := x509.MarshalPKIXPublicKey(&pkey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubkeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubkeyBytes,
	})
	rsaPubKey = base64.StdEncoding.EncodeToString(pubkeyPem)
	return
}

func TestNewAuthTokenSigner(t *testing.T) {
	hmacKey, rsaPrivKey, rsaPubKey := newTestKey(t)
	host := "test-host"

	t.Run("Success", func(t *testing.T) {
		t.Setenv("AUTH_HOST", host)
		t.Setenv("AUTH_TOKEN_HMAC_KEY", hmacKey)
		t.Setenv("AUTH_TOKEN_RSA_PRIV_KEY", rsaPrivKey)
		t.Setenv("AUTH_TOKEN_RSA_PUB_KEY", rsaPubKey)

		signer, err := NewAuthTokenSigner()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if signer == nil {
			t.Fatal("expected signer to be not nil")
		}
	})

	t.Run("MissingAuthHost", func(t *testing.T) {
		t.Setenv("AUTH_HOST", "")
		t.Setenv("AUTH_TOKEN_HMAC_KEY", hmacKey)
		t.Setenv("AUTH_TOKEN_RSA_PRIV_KEY", rsaPrivKey)
		t.Setenv("AUTH_TOKEN_RSA_PUB_KEY", rsaPubKey)

		_, err := NewAuthTokenSigner()
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("MissingHmacKey", func(t *testing.T) {
		t.Setenv("AUTH_HOST", host)
		t.Setenv("AUTH_TOKEN_HMAC_KEY", "")
		t.Setenv("AUTH_TOKEN_RSA_PRIV_KEY", rsaPrivKey)
		t.Setenv("AUTH_TOKEN_RSA_PUB_KEY", rsaPubKey)

		_, err := NewAuthTokenSigner()
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("MissingRsaPrivKey", func(t *testing.T) {
		t.Setenv("AUTH_HOST", host)
		t.Setenv("AUTH_TOKEN_HMAC_KEY", hmacKey)
		t.Setenv("AUTH_TOKEN_RSA_PRIV_KEY", "")
		t.Setenv("AUTH_TOKEN_RSA_PUB_KEY", rsaPubKey)

		_, err := NewAuthTokenSigner()
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("MissingRsaPubKey", func(t *testing.T) {
		t.Setenv("AUTH_HOST", host)
		t.Setenv("AUTH_TOKEN_HMAC_KEY", hmacKey)
		t.Setenv("AUTH_TOKEN_RSA_PRIV_KEY", rsaPrivKey)
		t.Setenv("AUTH_TOKEN_RSA_PUB_KEY", "")

		_, err := NewAuthTokenSigner()
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("MalformedHmacKey", func(t *testing.T) {
		t.Setenv("AUTH_HOST", host)
		t.Setenv("AUTH_TOKEN_HMAC_KEY", "invalid-key")
		t.Setenv("AUTH_TOKEN_RSA_PRIV_KEY", rsaPrivKey)
		t.Setenv("AUTH_TOKEN_RSA_PUB_KEY", rsaPubKey)

		_, err := NewAuthTokenSigner()
		if err == nil {
			t.Fatal("expected error on malformed hmac key")
		}
	})

	t.Run("MalformedRsaPrivKey", func(t *testing.T) {
		t.Setenv("AUTH_HOST", host)
		t.Setenv("AUTH_TOKEN_HMAC_KEY", hmacKey)
		t.Setenv("AUTH_TOKEN_RSA_PRIV_KEY", "invalid-key")
		t.Setenv("AUTH_TOKEN_RSA_PUB_KEY", rsaPubKey)

		_, err := NewAuthTokenSigner()
		if err == nil {
			t.Fatal("expected error on malformed rsa private key")
		}
	})

	t.Run("MalformedRsaPubKey", func(t *testing.T) {
		t.Setenv("AUTH_HOST", host)
		t.Setenv("AUTH_TOKEN_HMAC_KEY", hmacKey)
		t.Setenv("AUTH_TOKEN_RSA_PRIV_KEY", rsaPrivKey)
		t.Setenv("AUTH_TOKEN_RSA_PUB_KEY", "invalid-key")

		_, err := NewAuthTokenSigner()
		if err == nil {
			t.Fatal("expected error on malformed rsa public key")
		}
	})
}

func testAuthTokenSignerFlow(t *testing.T, method jwt.SigningMethod) {
	hmacKey, rsaPrivKey, rsaPubKey := newTestKey(t)
	host := "test-host"
	t.Setenv("AUTH_HOST", host)
	t.Setenv("AUTH_TOKEN_HMAC_KEY", hmacKey)
	t.Setenv("AUTH_TOKEN_RSA_PRIV_KEY", rsaPrivKey)
	t.Setenv("AUTH_TOKEN_RSA_PUB_KEY", rsaPubKey)

	signer, err := NewAuthTokenSigner()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	authID, _ := binid.NewRandom()
	userID, _ := binid.NewRandom()
	params := CreateAuthTokenParams{
		Method:    method,
		TokenType: TOKEN_TYPE_AUTHENTICATION,
		AuthId:    authID,
		UserId:    userID,
		Ttl:       time.Hour,
	}

	t.Run("CreateAndParse", func(t *testing.T) {
		tokenStr, err := signer.CreateAuthToken(params)
		if err != nil {
			t.Fatalf("create failed: %v", err)
		}

		claims, err := signer.Parse(ParseParams{Raw: tokenStr, Method: method, TokenType: params.TokenType})
		if err != nil {
			t.Fatalf("parse failed: %v", err)
		}

		if claims.Type != params.TokenType {
			t.Errorf("expected type %s, got %s", params.TokenType, claims.Type)
		}
		if claims.Subject != params.UserId.String() {
			t.Errorf("expected subject %s, got %s", params.UserId.String(), claims.Subject)
		}
		if claims.ID != params.AuthId.String() {
			t.Errorf("expected ID %s, got %s", params.AuthId.String(), claims.ID)
		}
		if claims.Version != AUTHENTICATED_TOKEN_VERSION {
			t.Errorf("expected version %s, got %s", AUTHENTICATED_TOKEN_VERSION, claims.Version)
		}
		if claims.Issuer != host {
			t.Errorf("expected issuer %s, got %s", host, claims.Issuer)
		}
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		expiredParams := params
		expiredParams.Ttl = -time.Hour

		tokenStr, err := signer.CreateAuthToken(expiredParams)
		if err != nil {
			t.Fatalf("create failed: %v", err)
		}

		_, err = signer.Parse(ParseParams{Raw: tokenStr, Method: method})
		if !errors.Is(err, jwt.ErrTokenExpired) {
			t.Fatalf("expected error for expired token, but got %v", err)
		}
	})

	t.Run("InvalidTokenString", func(t *testing.T) {
		_, err := signer.Parse(ParseParams{Raw: "invalid", Method: method})
		if err == nil {
			t.Fatal("expected error for invalid token string")
		}
	})
}

func TestAuthTokenSigner_Flow_HS256(t *testing.T) {
	testAuthTokenSignerFlow(t, jwt.SigningMethodHS256)
}

func TestAuthTokenSigner_Flow_RS256(t *testing.T) {
	testAuthTokenSignerFlow(t, jwt.SigningMethodRS256)
}
