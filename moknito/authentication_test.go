package moknito

import (
	"net/http"
	"net/url"
	"testing"
)

func TestAuthentication_NoAuthCookie(t *testing.T) {
	client := newTestClient()

	// First get a session
	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	resp.Body.Close()

	// Try to access endpoint that requires authentication
	resp, err = postForm(client, "/api/app/00000000-0000-7000-8000-000000000000/allow", nil, testServer.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should be forbidden without auth cookie
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected status 403 without auth cookie, got %d", resp.StatusCode)
	}
}

func TestAuthentication_InvalidAuthCookie(t *testing.T) {
	client := newTestClient()

	// First get a session
	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	resp.Body.Close()

	// Set invalid auth cookie
	serverURL, _ := url.Parse(testServer.URL)
	client.Jar.SetCookies(serverURL, []*http.Cookie{
		{Name: "ae", Value: "invalid.jwt.token", Path: "/"},
	})

	// Try to access endpoint that requires authentication
	resp, err = postForm(client, "/api/app/00000000-0000-7000-8000-000000000000/allow", nil, testServer.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should be bad request for invalid JWT
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for invalid auth cookie, got %d", resp.StatusCode)
	}
}
