package moknito

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestOriginGuard(t *testing.T) {
	t.Run("BadRequest if missing Origin", func(t *testing.T) {
		m, _ := setupTestMoknito()

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		// No Origin header
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		h := m.OriginGuard()(func(c echo.Context) error {
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

	t.Run("BadRequest if empty Origin", func(t *testing.T) {
		m, _ := setupTestMoknito()

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Origin", "")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		h := m.OriginGuard()(func(c echo.Context) error {
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

	t.Run("BadRequest if incorrect Origin", func(t *testing.T) {
		m, _ := setupTestMoknito()
		// m.origin is "http://test.com"

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Origin", "http://attacker.com")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		h := m.OriginGuard()(func(c echo.Context) error {
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

	t.Run("Success if correct Origin", func(t *testing.T) {
		m, _ := setupTestMoknito()
		// m.origin is "http://test.com"

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Origin", "http://test.com")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		h := m.OriginGuard()(func(c echo.Context) error {
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
