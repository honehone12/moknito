package moknito

import (
	"net/http"
	"net/url"
	"testing"
)

func TestOrigin_OriginGuard(t *testing.T) {
	client := newTestClient()

	// First get a session
	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	resp.Body.Close()

	// Test with no Origin header
	data := url.Values{}
	resp, err = postForm(client, "/api/user/00000000-0000-7000-8000-000000000000/register", data, "")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for missing origin, got %d", resp.StatusCode)
	}

	// Test with wrong Origin header
	resp2, err := postForm(client, "/api/user/00000000-0000-7000-8000-000000000000/register", data, "http://evil.com")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for wrong origin, got %d", resp2.StatusCode)
	}

	// Test with correct Origin header (should fail at validation, not origin)
	resp3, err := postForm(client, "/api/user/00000000-0000-7000-8000-000000000000/register", data, testServer.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp3.Body.Close()

	// Should pass origin check but fail validation (empty form)
	if resp3.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for invalid form, got %d", resp3.StatusCode)
	}
}
