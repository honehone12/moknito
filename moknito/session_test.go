package moknito

import (
	"context"
	"errors"
	"moknito/sys"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
)

func setupTestMoknito() (*Moknito, *MockSys) {
	mockSys := &MockSys{}
	v := validator.New()
	m := &Moknito{
		system:    mockSys,
		validator: v,
		origin:    "http://test.com",
	}
	return m, mockSys
}

func TestSetSession(t *testing.T) {
	t.Run("Create Cookie if missing", func(t *testing.T) {
		m, mockSys := setupTestMoknito()

		mockSys.CreateSessionFunc = func(ctx context.Context) (*http.Cookie, error) {
			return &http.Cookie{Name: sys.SESSION_COOKIE_KEY, Value: "new-session"}, nil
		}

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		h := m.SetSession()(func(c echo.Context) error {
			return c.String(http.StatusOK, "OK")
		})

		if err := h(c); err != nil {
			t.Fatalf("handler error: %v", err)
		}

		cookie := rec.Result().Cookies()[0]
		if cookie.Value != "new-session" {
			t.Errorf("Expected cookie value 'new-session', got '%s'", cookie.Value)
		}
	})

	t.Run("Verify and Increment if valid", func(t *testing.T) {
		m, mockSys := setupTestMoknito()

		mockSys.VerifySessionFunc = func(ctx context.Context, cookie *http.Cookie) (*http.Cookie, error, error) {
			// Return incremented cookie
			return &http.Cookie{Name: sys.SESSION_COOKIE_KEY, Value: "incremented-session"}, nil, nil
		}

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		// valid cookie format (min 44 chars)
		// We need a dummy valid format string that passes validator: "min=44,base64rawurl"
		// 44 chars of base64url matches [A-Za-z0-9-_]
		dummyCookieVal := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		req.AddCookie(&http.Cookie{Name: sys.SESSION_COOKIE_KEY, Value: dummyCookieVal})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		h := m.SetSession()(func(c echo.Context) error {
			return c.String(http.StatusOK, "OK")
		})

		if err := h(c); err != nil {
			t.Fatalf("handler error: %v", err)
		}

		cookie := rec.Result().Cookies()[0]
		if cookie.Value != "incremented-session" {
			t.Errorf("Expected cookie value 'incremented-session', got '%s'", cookie.Value)
		}
	})

	t.Run("Recreate if Invalid Session returned by Verify", func(t *testing.T) {
		m, mockSys := setupTestMoknito()

		mockSys.VerifySessionFunc = func(ctx context.Context, cookie *http.Cookie) (*http.Cookie, error, error) {
			// Return validation error
			return nil, errors.New("invalid signature"), nil
		}
		mockSys.CreateSessionFunc = func(ctx context.Context) (*http.Cookie, error) {
			return &http.Cookie{Name: sys.SESSION_COOKIE_KEY, Value: "regenerated-session"}, nil
		}

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		dummyCookieVal := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		req.AddCookie(&http.Cookie{Name: sys.SESSION_COOKIE_KEY, Value: dummyCookieVal})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		h := m.SetSession()(func(c echo.Context) error {
			return c.String(http.StatusOK, "OK")
		})

		if err := h(c); err != nil {
			t.Fatalf("handler error: %v", err)
		}

		cookie := rec.Result().Cookies()[0]
		if cookie.Value != "regenerated-session" {
			t.Errorf("Expected cookie value 'regenerated-session', got '%s'", cookie.Value)
		}
	})
}

func TestVerifySession(t *testing.T) {
	t.Run("Forbidden if missing cookie", func(t *testing.T) {
		m, _ := setupTestMoknito()

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		h := m.VerifySession()(func(c echo.Context) error {
			return c.String(http.StatusOK, "OK")
		})

		err := h(c)
		if err != nil {
			he, ok := err.(*echo.HTTPError)
			if !ok || he.Code != http.StatusForbidden {
				t.Errorf("Expected 403 Forbidden, got %v", err)
			}
		} else {
			// or response code
			if rec.Code != http.StatusForbidden {
				t.Errorf("Expected 403 Forbidden, got %d", rec.Code)
			}
		}
	})

	t.Run("BadRequest if invalid cookie format", func(t *testing.T) {
		m, _ := setupTestMoknito()

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: sys.SESSION_COOKIE_KEY, Value: "short"})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		h := m.VerifySession()(func(c echo.Context) error {
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

	t.Run("BadRequest if Verify returns error", func(t *testing.T) {
		m, mockSys := setupTestMoknito()

		mockSys.VerifySessionFunc = func(ctx context.Context, cookie *http.Cookie) (*http.Cookie, error, error) {
			return nil, errors.New("invalid"), nil
		}

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		dummyCookieVal := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		req.AddCookie(&http.Cookie{Name: sys.SESSION_COOKIE_KEY, Value: dummyCookieVal})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		h := m.VerifySession()(func(c echo.Context) error {
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
	
	t.Run("Success calls next", func(t *testing.T) {
		m, mockSys := setupTestMoknito()

		mockSys.VerifySessionFunc = func(ctx context.Context, cookie *http.Cookie) (*http.Cookie, error, error) {
			return &http.Cookie{Name: sys.SESSION_COOKIE_KEY, Value: "new"}, nil, nil
		}

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		dummyCookieVal := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		req.AddCookie(&http.Cookie{Name: sys.SESSION_COOKIE_KEY, Value: dummyCookieVal})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		h := m.VerifySession()(func(c echo.Context) error {
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
