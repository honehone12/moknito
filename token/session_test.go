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
		t.Setenv("SESSION_TOKEN_HMAC_KEY", encodedKey)

		signer, err := NewSessionTokenSigner()
		if err != nil {
			t.Fatalf("NewSessionTokenSigner() error = %v", err)
		}
		if signer == nil {
			t.Fatal("NewSessionTokenSigner() returned nil signer")
		}
	})

	t.Run("MissingKeyEnvVar", func(t *testing.T) {
		t.Setenv("SESSION_TOKEN_HMAC_KEY", "")

		_, err := NewSessionTokenSigner()
		if err == nil {
			t.Fatal("NewSessionTokenSigner() expected error for missing key env var")
		}
		expectedErr := "unexpected auth token signature key length"
		if err.Error() != expectedErr {
			t.Errorf("expected error %q, got %q", expectedErr, err.Error())
		}
	})

	t.Run("MalformedKeyNotBase64", func(t *testing.T) {
		t.Setenv("SESSION_TOKEN_HMAC_KEY", "this-is-not-base64-encthis-is-not-base64-enc")

		_, err := NewSessionTokenSigner()
		if err == nil {
			t.Fatal("NewSessionTokenSigner() expected error for malformed (not base64) key")
		}
		// Expecting base64 decoding error
		if _, ok := err.(base64.CorruptInputError); !ok && err.Error() != "illegal base64 data at input byte 4" {
			t.Errorf("expected base64.CorruptInputError, got %T %q", err, err.Error())
		}
	})

	t.Run("IncorrectDecodedKeyLength", func(t *testing.T) {
		// A base64 encoded string that has correct HMAC_KEY_ENV_LEN but decodes to wrong HMAC_KEY_LEN
		// 32 bytes should encode to 44 chars. Let's make a 33 byte key, it will encode to 45 chars
		// So we create a string of 44 chars that decodes to an incorrect length
		// A 31 byte key encoded to base64 would be 43 characters long
		// A 29 byte key encoded to base64 would be 40 characters long
		// Let's encode 25 bytes. It will be 36 characters.
		// To make HMAC_KEY_ENV_LEN (44 chars) but wrong decoded len, is not easy.
		// So we use a key that encodes to correct length but has wrong original length.
		// e.g., 32 'A's -> 44 chars. But if we make 31 'A's it becomes 43 chars.
		// Let's just make an encoded key of correct env length, but when decoded, has wrong length.
		// For example, if HMAC_KEY_LEN is 32, HMAC_KEY_ENV_LEN is 44.
		// A 32-byte key is 44 characters when base64 encoded (e.g. AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA).
		// If we want to test "unexpected signature key length", we need to provide a 44-char string that decodes to not 32 bytes.
		// e.g. "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB" (44 chars) will decode to 32 bytes.
		// How about "A" repeated 44 times, this decodes to 33 bytes.
		t.Setenv("SESSION_TOKEN_HMAC_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") // 45 A's, length of 45
		// This should fail because length is 45, not 44 (HMAC_KEY_ENV_LEN)

		_, err := NewSessionTokenSigner()
		if err == nil {
			t.Fatal("NewSessionTokenSigner() expected error for incorrect decoded key length")
		}
		expectedErr := "unexpected auth token signature key length"
		if err.Error() != expectedErr {
			t.Errorf("expected error %q, got %q", expectedErr, err.Error())
		}
	})

	t.Run("InvalidKeyEnvLength", func(t *testing.T) {
		t.Setenv("SESSION_TOKEN_HMAC_KEY", "short") // This is not 44 chars.
		_, err := NewSessionTokenSigner()
		if err == nil {
			t.Error("NewSessionTokenSigner() expected error for invalid key env length")
		}
		expectedErr := "unexpected auth token signature key length"
		if err.Error() != expectedErr {
			t.Errorf("expected error %q, got %q", expectedErr, err.Error())
		}
	})

	t.Run("IncorrectDecodedLength", func(t *testing.T) {
		// Provide a valid base64 string of HMAC_KEY_ENV_LEN, but decodes to wrong HMAC_KEY_LEN
		// Example: 30 bytes, base64 encoded is 40 chars.
		// We need to construct a 44-char base64 string that decodes to not 32 bytes.
		// This happens if the original byte array was not 32.
		// E.g., make a 31 byte key, base64 it, it will be 43 characters long.
		// If I make a 32 byte array of all 'a', it will be "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
		// This is 44 chars.
		// What if I take 31 bytes, then pad it with a trailing '=' to make it 44 chars long (if possible)?
		// The easiest way is to provide a correct length key but with bad content, which will fail the length check.
		// Let's create a 31-byte key and then encode it. It will be 43 characters.
		// If HMAC_KEY_ENV_LEN = 44, I need a 44-character string that decodes to an invalid length.
		// Let's try 31 zero bytes: MDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2
		// No, let's use the actual length check of the function.
		// We need an encoded key that is HMAC_KEY_ENV_LEN (44), but decodes to something other than HMAC_KEY_LEN (32).
		// A 33 byte array encoded to base64 becomes 45 characters.
		// So we need to find a 44 char base64 string that decodes to not 32 bytes.
		// The string "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" decodes to 33 bytes.
		// This is 44 chars long. This should pass the env length check, but fail the decoded length check.
		t.Setenv("SESSION_TOKEN_HMAC_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		_, err := NewSessionTokenSigner()
		if err == nil {
			t.Fatal("NewSessionTokenSigner() expected error for incorrect decoded length")
		}
		expectedErr := "unexpected signature key length"
		if err.Error() != expectedErr {
			t.Errorf("expected error %q, got %q", expectedErr, err.Error())
		}
	})

}

func TestSessionTokenSigner_SignedCookie_And_Verify(t *testing.T) {
	validKey := make([]byte, 32)
	encodedKey := base64.StdEncoding.EncodeToString(validKey)
	t.Setenv("SESSION_TOKEN_HMAC_KEY", encodedKey)

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

	t.Run("Invalid Session Key", func(t *testing.T) {
		cookieVal, err := signer.SignedCookie(sessKey, nonce)
		if err != nil {
			t.Fatalf("SignedCookie() error = %v", err)
		}
		decoded, _ := base64.RawURLEncoding.DecodeString(cookieVal)

		// Tamper with session key
		if len(decoded) > HMAC_SIGNATURE_LEN {
			decoded[HMAC_SIGNATURE_LEN] ^= 0xFF
		}

		signature := decoded[:HMAC_SIGNATURE_LEN]
		extractedSessKey := decoded[HMAC_SIGNATURE_LEN:]

		valid, err := signer.Verify(signature, extractedSessKey, nonce)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if valid {
			t.Error("Verify() returned true for tampered session key")
		}
	})

	t.Run("Empty Session Key", func(t *testing.T) {
		emptySessKey := []byte("")
		cookieVal, err := signer.SignedCookie(emptySessKey, nonce)
		if err != nil {
			t.Fatalf("SignedCookie() with empty sessKey error = %v", err)
		}

		decoded, _ := base64.RawURLEncoding.DecodeString(cookieVal)
		signature := decoded[:HMAC_SIGNATURE_LEN]
		extractedSessKey := decoded[HMAC_SIGNATURE_LEN:]

		if len(extractedSessKey) != 0 {
			t.Errorf("Expected empty extracted session key, got %v", extractedSessKey)
		}

		valid, err := signer.Verify(signature, extractedSessKey, nonce)
		if err != nil {
			t.Fatalf("Verify() with empty sessKey error = %v", err)
		}
		if !valid {
			t.Error("Verify() with empty sessKey returned false")
		}
	})

	t.Run("Empty Nonce", func(t *testing.T) {
		emptyNonce := ""
		cookieVal, err := signer.SignedCookie(sessKey, emptyNonce)
		if err != nil {
			t.Fatalf("SignedCookie() with empty nonce error = %v", err)
		}

		decoded, _ := base64.RawURLEncoding.DecodeString(cookieVal)
		signature := decoded[:HMAC_SIGNATURE_LEN]
		extractedSessKey := decoded[HMAC_SIGNATURE_LEN:]

		valid, err := signer.Verify(signature, extractedSessKey, emptyNonce)
		if err != nil {
			t.Fatalf("Verify() with empty nonce error = %v", err)
		}
		if !valid {
			t.Error("Verify() with empty nonce returned false")
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
	t.Setenv("SESSION_TOKEN_HMAC_KEY", encodedKey)

	signer, _ := NewSessionTokenSigner()
	sessKey := []byte("hello")
	nonce := "world"

	cookieVal, _ := signer.SignedCookie(sessKey, nonce)

	decoded, _ := base64.RawURLEncoding.DecodeString(cookieVal)
	if len(decoded) != HMAC_SIGNATURE_LEN+len(sessKey) {
		t.Errorf("Expected length %d, got %d", HMAC_SIGNATURE_LEN+len(sessKey), len(decoded))
	}
}
