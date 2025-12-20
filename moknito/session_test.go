package moknito

import (
	"net/http"
	"testing"
)

func TestSession_SetSession(t *testing.T) {
	client := newTestClient()

	// First request should set a session cookie
	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// Check that session cookie was set
	cookies := resp.Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "ss" { // SESSION_COOKIE_KEY
			sessionCookie = c
			break
		}
	}

	if sessionCookie == nil {
		t.Error("session cookie not set")
	}

	// Second request should update the session cookie (increment nonce)
	resp2, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp2.StatusCode)
	}

	// Cookie should be different (new signature due to incremented nonce)
	cookies2 := resp2.Cookies()
	var sessionCookie2 *http.Cookie
	for _, c := range cookies2 {
		if c.Name == "ss" {
			sessionCookie2 = c
			break
		}
	}

	if sessionCookie2 == nil {
		t.Error("session cookie not updated on second request")
	}

	if sessionCookie != nil && sessionCookie2 != nil && sessionCookie.Value == sessionCookie2.Value {
		t.Error("session cookie should have different value after increment")
	}
}

func TestSession_VerifySession_NoCookie(t *testing.T) {
	client := newTestClient()

	// Request to route that requires valid session without providing one
	// /api/user endpoint requires VerifySession
	resp, err := postForm(client, "/api/user/00000000-0000-7000-8000-000000000000/register", nil, testServer.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should get Forbidden because no session cookie
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", resp.StatusCode)
	}
}
