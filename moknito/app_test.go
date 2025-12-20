package moknito

import (
	"net/http"
	"net/url"
	"testing"
)

func TestApp_Allow_NoAuth(t *testing.T) {
	client := newTestClient()

	// Get session first
	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	resp.Body.Close()

	// Try to allow app without authentication
	resp, err = postForm(client, "/api/app/00000000-0000-7000-8000-000000000000/allow", nil, testServer.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should be forbidden without auth cookie
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected status 403 without auth, got %d", resp.StatusCode)
	}
}

func TestApp_Authorize_NoAuth(t *testing.T) {
	client := newTestClient()

	// Get session first
	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	resp.Body.Close()

	// Try to authorize app without authentication
	resp, err = postForm(client, "/api/app/00000000-0000-7000-8000-000000000000/authorize", nil, testServer.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should be forbidden without auth cookie
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected status 403 without auth, got %d", resp.StatusCode)
	}
}

func TestApp_Allow_InvalidUUID(t *testing.T) {
	client := newTestClient()

	// Get session first
	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	resp.Body.Close()

	// Set auth cookie (invalid but will fail at validation first)
	serverURL, _ := url.Parse(testServer.URL)
	client.Jar.SetCookies(serverURL, []*http.Cookie{
		{Name: "ae", Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", Path: "/"},
	})

	// Try to allow app with invalid UUID
	resp, err = postForm(client, "/api/app/invalid-uuid/allow", nil, testServer.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should be bad request for invalid UUID
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for invalid UUID, got %d", resp.StatusCode)
	}
}

func TestApp_Authorize_InvalidUUID(t *testing.T) {
	client := newTestClient()

	// Get session first
	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	resp.Body.Close()

	// Set auth cookie (invalid but will fail at validation first)
	serverURL, _ := url.Parse(testServer.URL)
	client.Jar.SetCookies(serverURL, []*http.Cookie{
		{Name: "ae", Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", Path: "/"},
	})

	// Try to authorize app with invalid UUID
	resp, err = postForm(client, "/api/app/invalid-uuid/authorize", nil, testServer.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should be bad request for invalid UUID
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for invalid UUID, got %d", resp.StatusCode)
	}
}
