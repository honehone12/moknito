package moknito

import (
	"context"
	"errors"
	"moknito/sys"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestVerifyAuthentication(t *testing.T) {
	t.Run("Forbidden if missing cookie", func(t *testing.T) {
		m, _ := setupTestMoknito()

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		h := m.VerifyAuthentication()(func(c echo.Context) error {
			return c.String(http.StatusOK, "OK")
		})

		err := h(c)
		if err != nil {
			he, ok := err.(*echo.HTTPError)
			if !ok || he.Code != http.StatusForbidden {
				t.Errorf("Expected 403 Forbidden, got %v", err)
			}
		} else if rec.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %d", rec.Code)
		}
	})

	t.Run("BadRequest if invalid cookie format", func(t *testing.T) {
		m, _ := setupTestMoknito()

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: sys.AUTHENTICATED_COOKIE_KEY, Value: "short"})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		h := m.VerifyAuthentication()(func(c echo.Context) error {
			return c.String(http.StatusOK, "OK")
		})

		err := h(c)
		if err != nil {
			he, ok := err.(*echo.HTTPError)
			if !ok || he.Code != http.StatusBadRequest {
				t.Errorf("Expected 400 BadRequest, got %v", err)
			}
		} else if rec.Code != http.StatusBadRequest {
			t.Errorf("Expected 400 BadRequest, got %d", rec.Code)
		}
	})

	t.Run("BadRequest if Verify returns invalid", func(t *testing.T) {
		m, mockSys := setupTestMoknito()

		mockSys.VerifyAuthenticationFunc = func(ctx context.Context, cookie *http.Cookie) (error, error) {
			// verification error
			return errors.New("invalid token"), nil
		}

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		dummyCookieVal := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		req.AddCookie(&http.Cookie{Name: sys.AUTHENTICATED_COOKIE_KEY, Value: dummyCookieVal})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		h := m.VerifyAuthentication()(func(c echo.Context) error {
			return c.String(http.StatusOK, "OK")
		})

		err := h(c)
		if err != nil {
			he, ok := err.(*echo.HTTPError)
			if !ok || he.Code != http.StatusBadRequest {
				t.Errorf("Expected 400 BadRequest, got %v", err)
			}
		} else if rec.Code != http.StatusBadRequest {
			t.Errorf("Expected 400 BadRequest, got %d", rec.Code)
		}
	})

	t.Run("InternalServerError if Verify returns system error", func(t *testing.T) {
		m, mockSys := setupTestMoknito()

		mockSys.VerifyAuthenticationFunc = func(ctx context.Context, cookie *http.Cookie) (error, error) {
			// system error
			return nil, errors.New("system error")
		}

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		dummyCookieVal := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		req.AddCookie(&http.Cookie{Name: sys.AUTHENTICATED_COOKIE_KEY, Value: dummyCookieVal})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		h := m.VerifyAuthentication()(func(c echo.Context) error {
			return c.String(http.StatusOK, "OK")
		})

		err := h(c)
		if err == nil {
			t.Error("Expected error, got nil")
		} else {
			// Should return the error directly so it bubble up to central error handler
			if err.Error() != "system error" {
				t.Errorf("Expected 'system error', got %v", err)
			}
		}
	})
	
	t.Run("Success calls next", func(t *testing.T) {
		m, mockSys := setupTestMoknito()

		mockSys.VerifyAuthenticationFunc = func(ctx context.Context, cookie *http.Cookie) (error, error) {
			return nil, nil
		}

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		dummyCookieVal := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		req.AddCookie(&http.Cookie{Name: sys.AUTHENTICATED_COOKIE_KEY, Value: dummyCookieVal})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		h := m.VerifyAuthentication()(func(c echo.Context) error {
			return c.String(http.StatusOK, "OK")
		})

		if err := h(c); err != nil {
			t.Fatalf("handler error: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", rec.Code)
		}
	})
}
