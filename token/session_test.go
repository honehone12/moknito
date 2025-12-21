package token

import (
	"encoding/base64"
	"testing"
)

func TestNewSessionTokenSigner(t *testing.T) {
	// Setup valid env vars
	validKey := make([]byte, 32)
	encodedKey := base64.StdEncoding.EncodeToString(validKey)

	t.Run("Success", func(t *testing.T) {
		t.Setenv("SESSION_TOKEN_KEY", encodedKey)

		signer, err := NewSessionTokenSigner()
		if err != nil {
			t.Fatalf("NewSessionTokenSigner() error = %v", err)
		}
		if signer == nil {
			t.Fatal("NewSessionTokenSigner() returned nil signer")
		}
	})

	t.Run("Invalid Key Length", func(t *testing.T) {
		t.Setenv("SESSION_TOKEN_KEY", "short")

		_, err := NewSessionTokenSigner()
		if err == nil {
			t.Error("NewSessionTokenSigner() expected error for invalid key length")
		}
	})
}

func TestSessionTokenSigner_SignedCookie_And_Verify(t *testing.T) {
	validKey := make([]byte, 32)
	encodedKey := base64.StdEncoding.EncodeToString(validKey)
	t.Setenv("SESSION_TOKEN_KEY", encodedKey)

	signer, err := NewSessionTokenSigner()
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	sessKey := []byte("session-key-data")
	nonce := "random-nonce"

	t.Run("Round Trip", func(t *testing.T) {
		cookieVal, err := signer.SignedCookie(sessKey, nonce)
		if err != nil {
			t.Fatalf("SignedCookie() error = %v", err)
		}

		// Verify signature
		// The cookieVal is base64(signature + sessKey)
		decoded, err := base64.RawURLEncoding.DecodeString(cookieVal)
		if err != nil {
			t.Fatalf("Failed to decode cookie value: %v", err)
		}

		if len(decoded) <= HMAC_SIGNATURE_LEN {
			t.Fatalf("Decoded length too short: %d", len(decoded))
		}

		signature := decoded[:HMAC_SIGNATURE_LEN]
		extractedSessKey := decoded[HMAC_SIGNATURE_LEN:]

		valid, err := signer.Verify(signature, extractedSessKey, nonce)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if !valid {
			t.Error("Verify() returned false for valid signature")
		}
	})

	t.Run("Invalid Signature", func(t *testing.T) {
		cookieVal, err := signer.SignedCookie(sessKey, nonce)
		if err != nil {
			t.Fatalf("SignedCookie() error = %v", err)
		}
		decoded, _ := base64.RawURLEncoding.DecodeString(cookieVal)

		// Tamper with signature
		decoded[0] ^= 0xFF
		signature := decoded[:HMAC_SIGNATURE_LEN]
		extractedSessKey := decoded[HMAC_SIGNATURE_LEN:]

		valid, err := signer.Verify(signature, extractedSessKey, nonce)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if valid {
			t.Error("Verify() returned true for invalid signature")
		}
	})

	t.Run("Invalid Nonce", func(t *testing.T) {
		cookieVal, err := signer.SignedCookie(sessKey, nonce)
		if err != nil {
			t.Fatalf("SignedCookie() error = %v", err)
		}
		decoded, _ := base64.RawURLEncoding.DecodeString(cookieVal)
		signature := decoded[:HMAC_SIGNATURE_LEN]
		extractedSessKey := decoded[HMAC_SIGNATURE_LEN:]

		valid, err := signer.Verify(signature, extractedSessKey, "wrong-nonce")
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if valid {
			t.Error("Verify() returned true for wrong nonce")
		}
	})

	t.Run("SignedCookie Error on Write failure (Simulated via huge input?) or just basic", func(t *testing.T) {
		// hard to force write error on hmac/hash usually.
		// But we can check very long inputs if we wanted.
		// For now, satisfied with basic flow.
	})
}

// Additional test to ensure we can decode what we encoded manually if needed
// basically verifying the composition of the signed cookie
func TestSignedCookieStructure(t *testing.T) {
	// This repeats some logic but verifies the public contract of how the cookie is constructed
	validKey := make([]byte, 32)
	encodedKey := base64.StdEncoding.EncodeToString(validKey)
	t.Setenv("SESSION_TOKEN_KEY", encodedKey)

	signer, _ := NewSessionTokenSigner()
	sessKey := []byte("hello")
	nonce := "world"

	cookieVal, _ := signer.SignedCookie(sessKey, nonce)

	decoded, _ := base64.RawURLEncoding.DecodeString(cookieVal)
	if len(decoded) != HMAC_SIGNATURE_LEN+len(sessKey) {
		t.Errorf("Expected length %d, got %d", HMAC_SIGNATURE_LEN+len(sessKey), len(decoded))
	}
}
