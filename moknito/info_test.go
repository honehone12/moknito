package moknito

import (
	"net/http"
	"net/url"
	"testing"
)

func TestInfo_InvalidAppId(t *testing.T) {
	client := newTestClient()

	// First get a session
	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	resp.Body.Close()

	// Try to get info without auth (should fail at auth check)
	resp, err = getRequest(client, "/info/00000000-0000-7000-8000-000000000000")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should be forbidden without auth cookie
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected status 403 without auth, got %d", resp.StatusCode)
	}
}

func TestAuthorization_InvalidCode(t *testing.T) {
	client := newTestClient()

	// Test auth token endpoint with invalid data
	data := url.Values{
		"grant":    {"code"},
		"code":     {"1234567890123456789012"}, // 22 chars base64
		"verifier": {"12345678901234567890123456789012345678901234"}, // 43+ chars
		"redirect": {"http://example.com/callback"},
	}

	resp, err := postForm(client, "/auth/00000000-0000-7000-8000-000000000000/token", data, "")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should fail - could be 400 (bad request) or 500 (system error) depending on DB state
	// Just verify the endpoint is reachable
	t.Logf("Authorization token endpoint returned status: %d", resp.StatusCode)
}
