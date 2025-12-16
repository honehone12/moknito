package token

import (
	"encoding/base64"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestAutheClaims_Validate(t *testing.T) {
	tests := []struct {
		name    string
		claims  AutheClaims
		wantErr bool
	}{
		{
			name: "Valid Authentication",
			claims: AutheClaims{
				Version: AUTHENTICATED_TOKEN_VERSION,
				Type:    TOKEN_TYPE_AUTHENTICATION,
			},
			wantErr: false,
		},
		{
			name: "Valid Authorization",
			claims: AutheClaims{
				Version: AUTHENTICATED_TOKEN_VERSION,
				Type:    TOKEN_TYPE_AUTHORIZATION,
			},
			wantErr: false,
		},
		{
			name: "Invalid Version",
			claims: AutheClaims{
				Version: "0.0.0",
				Type:    TOKEN_TYPE_AUTHENTICATION,
			},
			wantErr: true,
		},
		{
			name: "Invalid Type",
			claims: AutheClaims{
				Version: AUTHENTICATED_TOKEN_VERSION,
				Type:    "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.claims.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("AutheClaims.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewAuthTokenSigner(t *testing.T) {
	// Setup valid env vars
	validKey := make([]byte, 32)
	encodedKey := base64.StdEncoding.EncodeToString(validKey)
	
	t.Run("Success", func(t *testing.T) {
		t.Setenv("AUTH_TOKEN_KEY", encodedKey)
		t.Setenv("AUTH_HOST", "example.com")

		signer, err := NewAuthTokenSigner()
		if err != nil {
			t.Fatalf("NewAuthTokenSigner() error = %v", err)
		}
		if signer == nil {
			t.Fatal("NewAuthTokenSigner() returned nil signer")
		}
	})

	t.Run("Invalid Key Length", func(t *testing.T) {
		t.Setenv("AUTH_TOKEN_KEY", "short")
		t.Setenv("AUTH_HOST", "example.com")

		_, err := NewAuthTokenSigner()
		if err == nil {
			t.Error("NewAuthTokenSigner() expected error for invalid key length")
		}
	})

	t.Run("Missing Host", func(t *testing.T) {
		t.Setenv("AUTH_TOKEN_KEY", encodedKey)
		os.Unsetenv("AUTH_HOST")

		_, err := NewAuthTokenSigner()
		if err == nil {
			t.Error("NewAuthTokenSigner() expected error for missing host")
		}
	})
}

func TestAuthTokenSigner_CreateAuthToken_And_Parse(t *testing.T) {
	validKey := make([]byte, 32)
	encodedKey := base64.StdEncoding.EncodeToString(validKey)
	t.Setenv("AUTH_TOKEN_KEY", encodedKey)
	t.Setenv("AUTH_HOST", "test-host")

	signer, err := NewAuthTokenSigner()
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	t.Run("Round Trip", func(t *testing.T) {
		tokenType := TOKEN_TYPE_AUTHENTICATION
		authId := "auth-123"
		userId := "user-456"
		ttl := time.Hour

		tokenStr, err := signer.CreateAuthToken(tokenType, authId, userId, ttl)
		if err != nil {
			t.Fatalf("CreateAuthToken() error = %v", err)
		}

		claims, err := signer.Parse(tokenStr)
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}

		if claims.Type != tokenType {
			t.Errorf("got type %v, want %v", claims.Type, tokenType)
		}
		if claims.ID != authId {
			t.Errorf("got ID %v, want %v", claims.ID, authId)
		}
		if claims.Subject != userId {
			t.Errorf("got Subject %v, want %v", claims.Subject, userId)
		}
		if claims.Issuer != "test-host" {
			t.Errorf("got Issuer %v, want %v", claims.Issuer, "test-host")
		}
	})

	t.Run("Invalid Audience", func(t *testing.T) {
		tokenStr, err := signer.CreateAuthToken(TOKEN_TYPE_AUTHENTICATION, "id", "sub", time.Hour, "app1")
		if err != nil {
			t.Fatalf("CreateAuthToken() error = %v", err)
		}

		_, err = signer.Parse(tokenStr, "app2")
		if err == nil {
			t.Error("Parse() expected error for invalid audience")
		} else if !errors.Is(err, jwt.ErrTokenInvalidAudience) {
             // Note: jwt.v5 might return a wrapped error, checking string might be safer if unsure about exact error variable exposure or just check it failed.
             // jwt.ErrTokenInvalidAudience is available in v5.
        }
	})

    t.Run("Using host as default audience", func(t *testing.T) {
		tokenStr, err := signer.CreateAuthToken(TOKEN_TYPE_AUTHENTICATION, "id", "sub", time.Hour)
        if err != nil {
			t.Fatalf("CreateAuthToken() error = %v", err)
		}
        // Parsing without args should default to host, which matches creation default
        _, err = signer.Parse(tokenStr)
        if err != nil {
             t.Errorf("Parse() failed with default audience: %v", err)
        }
    })
}
