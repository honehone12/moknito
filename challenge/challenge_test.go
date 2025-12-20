package challenge

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestVerify(t *testing.T) {
	// Setup valid case
	rawData := []byte("test-verifier-data")
	h := sha256.Sum256(rawData)
	storedHash := h[:]
	verifier := base64.RawURLEncoding.EncodeToString(rawData)

	t.Run("Valid", func(t *testing.T) {
		ok, err := Verify(verifier, storedHash)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ok {
			t.Error("expected verification to succeed")
		}
	})

	t.Run("Mismatch", func(t *testing.T) {
		otherData := []byte("other-data")
		otherH := sha256.Sum256(otherData)
		otherHash := otherH[:] // Different hash

		ok, err := Verify(verifier, otherHash)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ok {
			t.Error("expected verification to fail")
		}
	})

	t.Run("InvalidVerifierBase64", func(t *testing.T) {
		invalidVerifier := "invalid-base64-!!!"
		ok, err := Verify(invalidVerifier, storedHash)
		if err == nil {
			t.Error("expected error for invalid base64")
		}
		if ok {
			t.Error("expected verification to be false on error")
		}
	})
}
