package sys

import (
	"encoding/base64"
	"fmt"
	"moknito/token"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestSetSessionCookie(t *testing.T) {
	sys, mr := setupTestSys(t)
	// sys.tokenTtl is time.Hour

	t.Run("Create New Session", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		e := sys.SetSession()(func(c echo.Context) error {
			return nil
		})

		ctx := echo.New().NewContext(req, rec)
		if err := e(ctx); err != nil {
			t.Fatalf("Middleware returned error: %v", err)
		}

		// Check cookie set
		cookie := rec.Result().Cookies()[0]
		if cookie.Name != SESSION_COOKIE_KEY {
			t.Errorf("Expected cookie name %s, got %s", SESSION_COOKIE_KEY, cookie.Name)
		}

		// Verify redis has session
		// we need to decode cookie to get key
		decoded, _ := base64.RawURLEncoding.DecodeString(cookie.Value)
		sessKey := decoded[token.SIGNATURE_LEN:]

		// Check redis
		val, err := mr.Get(fmt.Sprintf("SESS:%x", sessKey))
		if err != nil {
			t.Fatalf("Redis key not found: %v", err)
		}
		if val != "0" {
			t.Errorf("Expected initial nonce 0, got %s", val)
		}
	})

	t.Run("Rotate Existing Session", func(t *testing.T) {
		// Create initial session manually
		// But better to use the middleware flow logic or manual helper?
		// Let's create one by calling the middleware first.
		req1 := httptest.NewRequest(http.MethodGet, "/", nil)
		rec1 := httptest.NewRecorder()
		ctx1 := echo.New().NewContext(req1, rec1)
		sys.SetSession()(func(c echo.Context) error { return nil })(ctx1)

		cookie := rec1.Result().Cookies()[0]

		// Now use this cookie in next request
		req2 := httptest.NewRequest(http.MethodGet, "/", nil)
		req2.AddCookie(cookie)
		rec2 := httptest.NewRecorder()
		ctx2 := echo.New().NewContext(req2, rec2)

		if err := sys.SetSession()(func(c echo.Context) error { return nil })(ctx2); err != nil {
			t.Fatalf("Middleware 2 returned error: %v", err)
		}

		// Should have updated cookie (nonce incremented)
		cookie2 := rec2.Result().Cookies()[0]
		if cookie2.Value == cookie.Value {
			t.Error("Cookie value should have changed (nonce increment)")
		}

		// Check redis
		decoded, _ := base64.RawURLEncoding.DecodeString(cookie2.Value)
		sessKey := decoded[token.SIGNATURE_LEN:]
		// Note: sessKey should be same

		// Check redis
		val, _ := mr.Get(fmt.Sprintf("SESS:%x", sessKey))
		if val != "1" {
			t.Errorf("Expected nonce 1, got %s", val)
		}
	})

	t.Run("Recreate if Invalid Session", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		// Invalid cookie (random string)
		req.AddCookie(&http.Cookie{Name: SESSION_COOKIE_KEY, Value: "invalid-cookie-value"})
		rec := httptest.NewRecorder()
		ctx := echo.New().NewContext(req, rec)

		if err := sys.SetSession()(func(c echo.Context) error { return nil })(ctx); err != nil {
			t.Fatalf("Middleware returned error: %v", err)
		}

		// Should set a NEW valid cookie
		if len(rec.Result().Cookies()) == 0 {
			t.Fatal("No cookie set")
		}
		// We can verify it's valid format
	})
}

func TestVerifySessionCookie(t *testing.T) {
	sys, mr := setupTestSys(t)

	t.Run("Valid Session", func(t *testing.T) {
		// Setup valid session manually in redis and generate cookie
		sessKey := []byte("valid-session-key")
		mr.Set(fmt.Sprintf("SESS:%x", sessKey), "10")

		cookieVal, _ := sys.sessionSigner.SignedCookie(sessKey, "10")

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: SESSION_COOKIE_KEY, Value: cookieVal})
		rec := httptest.NewRecorder()
		ctx := echo.New().NewContext(req, rec)

		handler := sys.VerifySession()(func(c echo.Context) error {
			return c.String(http.StatusOK, "OK")
		})

		if err := handler(ctx); err != nil {
			t.Fatalf("Handler returned error: %v", err)
		}

		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", rec.Code)
		}

		// Should increment nonce in Redis
		val, _ := mr.Get(fmt.Sprintf("SESS:%x", sessKey))
		if val != "11" {
			t.Errorf("Expected nonce 11, got %s", val)
		}
	})

	t.Run("Missing Session", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := echo.New().NewContext(req, rec)

		handler := sys.VerifySession()(func(c echo.Context) error {
			return c.String(http.StatusOK, "OK")
		})

		err := handler(ctx)
		// Verify middleware returns error (Forbidden)
		if err != nil {
			he, ok := err.(*echo.HTTPError)
			if !ok || he.Code != http.StatusForbidden {
				t.Errorf("Expected 403 Forbidden, got %v", err)
			}
		} else if rec.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %d", rec.Code)
		}
	})

	t.Run("Invalid Session (Signature mismatch)", func(t *testing.T) {
		sessKey := []byte("valid-session-key-2")
		mr.Set(fmt.Sprintf("SESS:%x", sessKey), "5")

		// Sign with WRONG nonce
		cookieVal, _ := sys.sessionSigner.SignedCookie(sessKey, "999")

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: SESSION_COOKIE_KEY, Value: cookieVal})
		rec := httptest.NewRecorder()
		ctx := echo.New().NewContext(req, rec)

		handler := sys.VerifySession()(func(c echo.Context) error {
			return c.String(http.StatusOK, "OK")
		})

		err := handler(ctx)
		if err != nil {
			he, ok := err.(*echo.HTTPError)
			if !ok || he.Code != http.StatusBadRequest {
				t.Errorf("Expected 400 BadRequest, got %v", err)
			}
		} else if rec.Code != http.StatusBadRequest {
			t.Errorf("Expected 400 BadRequest, got %d", rec.Code)
		}
	})

	t.Run("Session Not in Redis (Expired)", func(t *testing.T) {
		sessKey := []byte("expired-session-key")
		// Don't set in Redis (simulating expiration)

		cookieVal, _ := sys.sessionSigner.SignedCookie(sessKey, "0")

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: SESSION_COOKIE_KEY, Value: cookieVal})
		rec := httptest.NewRecorder()
		ctx := echo.New().NewContext(req, rec)

		handler := sys.VerifySession()(func(c echo.Context) error {
			return c.String(http.StatusOK, "OK")
		})

		err := handler(ctx)
		if err != nil {
			he, ok := err.(*echo.HTTPError)
			if !ok || he.Code != http.StatusBadRequest {
				t.Errorf("Expected 400 BadRequest, got %v", err)
			}
		} else if rec.Code != http.StatusBadRequest {
			t.Errorf("Expected 400 BadRequest, got %d", rec.Code)
		}
	})
}
