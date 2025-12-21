package sys

import (
	"context"
	"encoding/base64"
	"moknito/token"
	"testing"
)

func TestSession_CreateSession(t *testing.T) {
	sys, _ := setupSys(t)
	defer sys.Close()

	ctx := context.Background()
	cookie, err := sys.CreateSession(ctx)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	if cookie.Name != SESSION_COOKIE_KEY {
		t.Errorf("expected cookie name %s, got %s", SESSION_COOKIE_KEY, cookie.Name)
	}
	if cookie.Path != "/" {
		t.Errorf("expected cookie path /, got %s", cookie.Path)
	}
	if !cookie.HttpOnly {
		t.Error("expected cookie to be HttpOnly")
	}

	// Verify decoding the cookie
	dec, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		t.Errorf("failed to decode cookie value: %v", err)
	}
	if len(dec) <= token.HMAC_SIGNATURE_LEN {
		t.Errorf("cookie value too short")
	}
	sessKey := dec[token.HMAC_SIGNATURE_LEN:]
	if len(sessKey) != SESSION_KEY_LEN {
		t.Errorf("expected session key len %d, got %d", SESSION_KEY_LEN, len(sessKey))
	}
}

func TestSession_VerifySession(t *testing.T) {
	sys, _ := setupSys(t)
	defer sys.Close()
	ctx := context.Background()

	// 1. Create a valid session
	cookie, err := sys.CreateSession(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Verify it
	res := sys.VerifySession(ctx, cookie)
	if res.ValidationErr != nil {
		t.Errorf("verify failed validation: %v", res.ValidationErr)
	}
	if res.SystemErr != nil {
		t.Errorf("verify failed system: %v", res.SystemErr)
	}
	if len(res.SessionKey) != SESSION_KEY_LEN {
		t.Errorf("unexpected session key length")
	}

	// 3. Verify invalid signature
	invalidCookie := *cookie
	// Tamper with the signature (first byte)
	bytes, _ := base64.RawURLEncoding.DecodeString(invalidCookie.Value)
	bytes[0] ^= 0xFF
	invalidCookie.Value = base64.RawURLEncoding.EncodeToString(bytes)

	res = sys.VerifySession(ctx, &invalidCookie)
	if res.ValidationErr == nil {
		t.Error("expected validation error for tampered cookie, got nil")
	}

	// 4. Verify expired/missing session in redis
	// Clear redis
	sys.redis.FlushAll(ctx)
	res = sys.VerifySession(ctx, cookie)
	if res.ValidationErr == nil {
		t.Error("expected validation error for missing redis session, got nil")
	}
}

func TestSession_IncrSession(t *testing.T) {
	sys, _ := setupSys(t)
	defer sys.Close()
	ctx := context.Background()

	cookie, err := sys.CreateSession(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Extract sessKey
	dec, _ := base64.RawURLEncoding.DecodeString(cookie.Value)
	sessKey := dec[token.HMAC_SIGNATURE_LEN:]

	// Incr
	newCookie, err := sys.IncrSession(ctx, sessKey)
	if err != nil {
		t.Fatalf("IncrSession failed: %v", err)
	}

	if newCookie.Value == cookie.Value {
		t.Error("expected new cookie value to be different (new nonce signature)")
	}

	// Verify the new cookie works
	res := sys.VerifySession(ctx, newCookie)
	if res.ValidationErr != nil {
		t.Errorf("VerifySession failed for incremented session: %v", res.ValidationErr)
	}
}
