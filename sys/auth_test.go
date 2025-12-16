package sys

import (
	"context"
	"moknito/id"
	"moknito/token"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
)

func TestVerifyAuthenticatedCookie(t *testing.T) {
	sys, _ := setupTestSys(t)
    ctx := context.Background()

	// 1. Setup Data: User and Auth
    userIdVal, _ := id.NewRandom()
    usr, err := sys.ent.User.Create().
        SetID(string(userIdVal)).
        SetEmail("test@example.com").
        SetPwhash("hash").
        SetName("Test User").
        SetCreatedAt(time.Now()).
        SetUpdatedAt(time.Now()).
        Save(ctx)
    if err != nil {
        t.Fatalf("failed to create user: %v", err)
    }

    authIdVal, _ := id.NewRandom()
    auth, err := sys.ent.Authentication.Create().
        SetID(string(authIdVal)).
        SetUser(usr).
        SetIP("127.0.0.1").
        SetUserAgent("TestAgent").
        SetExpireAt(time.Now().Add(time.Hour)).
        Save(ctx)
    if err != nil {
        t.Fatalf("failed to create auth: %v", err)
    }

	// Helper to create token
    createToken := func(tType, aId, uId string, ttl time.Duration) string {
        tk, err := sys.authSigner.CreateAuthToken(tType, aId, uId, ttl)
        if err != nil {
            t.Fatalf("failed to create token: %v", err)
        }
        return tk
    }

    testCases := []struct {
        name           string
        setupCookie    func() *http.Cookie
        expectedStatus int
    }{
        {
            name: "Valid Token",
            setupCookie: func() *http.Cookie {
                aUUID, _ := id.Id(auth.ID).ToUUID()
                uUUID, _ := id.Id(usr.ID).ToUUID()
                tk := createToken(token.TOKEN_TYPE_AUTHENTICATION, aUUID.String(), uUUID.String(), time.Hour)
                return &http.Cookie{Name: AUTHENTICATED_COOKIE_KEY, Value: tk}
            },
            expectedStatus: http.StatusOK,
        },
        {
            name: "Missing Cookie",
            setupCookie: func() *http.Cookie {
                return nil
            },
            expectedStatus: http.StatusForbidden,
        },
        {
            name: "Invalid Token (Tampered)",
            setupCookie: func() *http.Cookie {
                tk := createToken(token.TOKEN_TYPE_AUTHENTICATION, string(auth.ID), string(usr.ID), time.Hour)
                return &http.Cookie{Name: AUTHENTICATED_COOKIE_KEY, Value: tk + "tamperd"}
            },
            expectedStatus: http.StatusBadRequest,
        },
        {
            name: "Token ID mismatch (Non-existent Auth ID)",
            setupCookie: func() *http.Cookie {
                newAuthId, _ := id.NewRandom() // not in DB
                tk := createToken(token.TOKEN_TYPE_AUTHENTICATION, string(newAuthId), string(usr.ID), time.Hour)
                return &http.Cookie{Name: AUTHENTICATED_COOKIE_KEY, Value: tk}
            },
            expectedStatus: http.StatusBadRequest,
        },
        {
            name: "User ID mismatch (Auth exists but User differs)",
            setupCookie: func() *http.Cookie {
                otherUser, _ := id.NewRandom()
                tk := createToken(token.TOKEN_TYPE_AUTHENTICATION, string(auth.ID), string(otherUser), time.Hour)
                return &http.Cookie{Name: AUTHENTICATED_COOKIE_KEY, Value: tk}
            },
            expectedStatus: http.StatusBadRequest,
        },
        {
            name: "Expired Auth in DB",
            setupCookie: func() *http.Cookie {
                // Create expired auth in DB
                expiredAuthId, _ := id.NewRandom()
                _, err := sys.ent.Authentication.Create().
                    SetID(string(expiredAuthId)).
                    SetUser(usr).
                    SetIP("127.0.0.1").
                    SetUserAgent("TestAgent").
                    SetExpireAt(time.Now().Add(-time.Hour)). // Expired
                    Save(ctx)
                if err != nil {
                    t.Fatalf("failed to create expired auth: %v", err)
                }
                
                tk := createToken(token.TOKEN_TYPE_AUTHENTICATION, string(expiredAuthId), string(usr.ID), time.Hour)
                return &http.Cookie{Name: AUTHENTICATED_COOKIE_KEY, Value: tk}
            },
            expectedStatus: http.StatusBadRequest,
        },
    }

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
            cookie := tc.setupCookie()
            if cookie != nil {
                req.AddCookie(cookie)
            }
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			handler := sys.VerifyAuthenticatedCookie()(func(c echo.Context) error {
				return c.String(http.StatusOK, "OK")
			})

			err := handler(c)
            var status int
            if err != nil {
                he, ok := err.(*echo.HTTPError)
                if ok {
                    status = he.Code
                } else {
                    t.Errorf("Handler returned unexpected error type: %v", err)
                    return
                }
            } else {
                status = rec.Code
            }

			if status != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d", tc.expectedStatus, status)
			}
		})
	}
}

func TestCreateAuthenticatedCookie(t *testing.T) {
	sys, _ := setupTestSys(t)

	authId, _ := id.NewRandom()
	userId, _ := id.NewRandom()

	cookie, err := sys.createAuthenticatedCookie(authId, userId)
	if err != nil {
		t.Fatalf("failed to create authenticated cookie: %v", err)
	}

	if cookie.Name != AUTHENTICATED_COOKIE_KEY {
		t.Errorf("expected cookie name %s, got %s", AUTHENTICATED_COOKIE_KEY, cookie.Name)
	}

	if cookie.Value == "" {
		t.Error("expected cookie value to be set")
	}

	if cookie.Path != "/" {
		t.Errorf("expected cookie path /, got %s", cookie.Path)
	}

	if cookie.MaxAge != int(sys.tokenTtl.Seconds()) {
		t.Errorf("expected cookie max age %d, got %d", int(sys.tokenTtl.Seconds()), cookie.MaxAge)
	}

	if cookie.Secure {
		t.Error("expected cookie secure to be false (for local)")
	}

	if !cookie.HttpOnly {
		t.Error("expected cookie http only to be true")
	}

	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("expected cookie same site %v, got %v", http.SameSiteStrictMode, cookie.SameSite)
	}
}
