package token

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNewAuthTokenSigner(t *testing.T) {
	// 32 bytes key
	validKey := make([]byte, 32)
	for i := 0; i < 32; i++ {
		validKey[i] = byte(i)
	}
	validKeyStr := base64.StdEncoding.EncodeToString(validKey)

	t.Run("Success", func(t *testing.T) {
		t.Setenv("AUTH_TOKEN_KEY", validKeyStr)
		t.Setenv("AUTH_HOST", "test-host")

		signer, err := NewAuthTokenSigner()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if signer == nil {
			t.Fatal("expected signer to be not nil")
		}
	})

	t.Run("InvalidKeyLength", func(t *testing.T) {
		t.Setenv("AUTH_TOKEN_KEY", "short")
		t.Setenv("AUTH_HOST", "test-host")

		_, err := NewAuthTokenSigner()
		if err == nil {
			t.Fatal("expected error for short key")
		}
	})

	t.Run("InvalidKeyEncoding", func(t *testing.T) {
		// Length 44 but invalid base64
		invalid := "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" 
		t.Setenv("AUTH_TOKEN_KEY", invalid)
		t.Setenv("AUTH_HOST", "test-host")

		_, err := NewAuthTokenSigner()
		if err == nil {
			t.Fatal("expected error for invalid encoding")
		}
	})

	t.Run("MissingHost", func(t *testing.T) {
		t.Setenv("AUTH_TOKEN_KEY", validKeyStr)
		t.Setenv("AUTH_HOST", "")

		_, err := NewAuthTokenSigner()
		if err == nil {
			t.Fatal("expected error for missing host")
		}
	})
}

func TestAuthTokenSigner_Flow(t *testing.T) {
	// Setup valid signer
	validKey := make([]byte, 32)
	for i := 0; i < 32; i++ {
		validKey[i] = byte(i)
	}
	validKeyStr := base64.StdEncoding.EncodeToString(validKey)
	t.Setenv("AUTH_TOKEN_KEY", validKeyStr)
	t.Setenv("AUTH_HOST", "test-host")

	signer, err := NewAuthTokenSigner()
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	params := CreateAuthTokenParams{
		TokenType: TOKEN_TYPE_AUTHENTICATION,
		AuthUuid:  uuid.New(),
		UserUuid:  uuid.New(),
		Ttl:       time.Hour,
	}

	t.Run("CreateAndParse", func(t *testing.T) {
		tokenStr, err := signer.CreateAuthToken(params)
		if err != nil {
			t.Fatalf("create failed: %v", err)
		}
		if tokenStr == "" {
			t.Fatal("expected token string")
		}

		claims, err := signer.Parse(tokenStr)
		if err != nil {
			t.Fatalf("parse failed: %v", err)
		}
		
		if claims.Type != params.TokenType {
			t.Errorf("expected type %s, got %s", params.TokenType, claims.Type)
		}
		if claims.Subject != params.UserUuid.String() {
			t.Errorf("expected subject %s, got %s", params.UserUuid.String(), claims.Subject)
		}
		if claims.ID != params.AuthUuid.String() {
			t.Errorf("expected ID %s, got %s", params.AuthUuid.String(), claims.ID)
		}
		if claims.Version != AUTHENTICATED_TOKEN_VERSION {
			t.Errorf("expected version %s, got %s", AUTHENTICATED_TOKEN_VERSION, claims.Version)
		}
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		expiredParams := params
		expiredParams.Ttl = -time.Hour // Expired

		tokenStr, err := signer.CreateAuthToken(expiredParams)
		if err != nil {
			t.Fatalf("create failed: %v", err)
		}

		_, err = signer.Parse(tokenStr)
		if err == nil {
			t.Fatal("expected error for expired token")
		}
	})
}
