package sys

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"moknito/token"
	"net/http"
	"testing"

	"github.com/redis/go-redis/v9"
)

func TestCreateSession(t *testing.T) {
	sys, mr := setupTestSys(t)
	ctx := context.Background()

	t.Run("Create New Session", func(t *testing.T) {
		cookie, err := sys.CreateSession(ctx)
		if err != nil {
			t.Fatalf("CreateSession returned error: %v", err)
		}

		if cookie.Name != SESSION_COOKIE_KEY {
			t.Errorf("Expected cookie name %s, got %s", SESSION_COOKIE_KEY, cookie.Name)
		}

		// Verify redis has session
		decoded, _ := base64.RawURLEncoding.DecodeString(cookie.Value)
		sessKey := decoded[token.SIGNATURE_LEN:]

		val, err := mr.Get(fmt.Sprintf("SESS:%x", sessKey))
		if err != nil {
			t.Fatalf("Redis key not found: %v", err)
		}
		if val != "0" {
			t.Errorf("Expected initial nonce 0, got %s", val)
		}
	})
}

func TestRotateSession(t *testing.T) {
	sys, mr := setupTestSys(t)
	ctx := context.Background()

	// 1. Create a session first
	cookie, err := sys.CreateSession(ctx)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// 2. Extract key
	decoded, _ := base64.RawURLEncoding.DecodeString(cookie.Value)
	sessKey := decoded[token.SIGNATURE_LEN:]

	// 3. Rotate (IncrSession)
	newCookie, err := sys.IncrSession(ctx, sessKey)
	if err != nil {
		t.Fatalf("IncrSession returned error: %v", err)
	}

	// 4. Check new cookie
	if newCookie.Value == cookie.Value {
		t.Error("Cookie value should have changed (nonce increment)")
	}

	// 5. Check Redis
	val, _ := mr.Get(fmt.Sprintf("SESS:%x", sessKey))
	if val != "1" {
		t.Errorf("Expected nonce 1, got %s", val)
	}
}

func TestVerifySessionCookie(t *testing.T) {
	sys, mr := setupTestSys(t)
	ctx := context.Background()

	t.Run("Valid Session", func(t *testing.T) {
		// Setup valid session manually in redis and generate cookie
		sessKey := []byte("0123456789012345") // 16 bytes
		mr.Set(fmt.Sprintf("SESS:%x", sessKey), "10")

		cookieVal, _ := sys.sessionSigner.SignedCookie(sessKey, "10")
		cookie := &http.Cookie{Name: SESSION_COOKIE_KEY, Value: cookieVal}

		newCookie, verErr, sysErr := sys.VerifySession(ctx, cookie)

		if verErr != nil {
			t.Errorf("Expected success, got verification error: %v", verErr)
		}
		if sysErr != nil {
			t.Errorf("Expected success, got system error: %v", sysErr)
		}

		if newCookie == nil {
			t.Fatal("Expected new cookie, got nil")
		}

		// Should increment nonce in Redis
		val, _ := mr.Get(fmt.Sprintf("SESS:%x", sessKey))
		if val != "11" {
			t.Errorf("Expected nonce 11, got %s", val)
		}
	})

	t.Run("Invalid Session (Signature mismatch)", func(t *testing.T) {
		sessKey := []byte("1123456789012345") // distinct 16 bytes
		mr.Set(fmt.Sprintf("SESS:%x", sessKey), "5")

		// Sign with WRONG nonce
		cookieVal, _ := sys.sessionSigner.SignedCookie(sessKey, "999")
		cookie := &http.Cookie{Name: SESSION_COOKIE_KEY, Value: cookieVal}

		_, verErr, sysErr := sys.VerifySession(ctx, cookie)

		if verErr == nil {
			t.Error("Expected verification error, got nil")
		}
		if sysErr != nil {
			t.Errorf("Expected verification error only, got system error: %v", sysErr)
		}
	})

	t.Run("Session Not in Redis (Expired)", func(t *testing.T) {
		sessKey := []byte("2123456789012345") // distinct 16 bytes
		// Don't set in Redis (simulating expiration)

		cookieVal, _ := sys.sessionSigner.SignedCookie(sessKey, "0")
		cookie := &http.Cookie{Name: SESSION_COOKIE_KEY, Value: cookieVal}

		_, verErr, sysErr := sys.VerifySession(ctx, cookie)

		// This might be treated as verification error or just redis nil error depending on impl
		// Looking at impl:
		// nonce, err := s.redis.Get(ctx, key).Result()
		// if errors.Is(err, redis.Nil) { return nil, err, nil }
		if verErr == nil {
			t.Error("Expected verification error (redis nil -> err), got nil")
		}
		// Based on code:
		// if errors.Is(err, redis.Nil) { return nil, err, nil }
		// so it returns verErr=redis.Nil, sysErr=nil
		if !errors.Is(verErr, redis.Nil) {
			t.Errorf("Expected redis.Nil error, got %T: %v", verErr, verErr)
		}

		if sysErr != nil {
			t.Errorf("Expected no system error, got %v", sysErr)
		}
	})
}
