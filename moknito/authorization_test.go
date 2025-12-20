package moknito

import (
	"net/http"
	"net/url"
	"testing"
)

func TestAuthorization_TokenEndpoint_InvalidGrant(t *testing.T) {
	client := newTestClient()

	// Test with invalid grant type
	data := url.Values{
		"grant":    {"invalid"},
		"code":     {"1234567890123456789012"},
		"verifier": {"12345678901234567890123456789012345678901234"},
		"redirect": {"http://example.com/callback"},
	}

	resp, err := postForm(client, "/auth/00000000-0000-7000-8000-000000000000/token", data, "")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for invalid grant, got %d", resp.StatusCode)
	}
}

func TestAuthorization_TokenEndpoint_ShortCode(t *testing.T) {
	client := newTestClient()

	// Test with too short code
	data := url.Values{
		"grant":    {"code"},
		"code":     {"short"},
		"verifier": {"12345678901234567890123456789012345678901234"},
		"redirect": {"http://example.com/callback"},
	}

	resp, err := postForm(client, "/auth/00000000-0000-7000-8000-000000000000/token", data, "")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for short code, got %d", resp.StatusCode)
	}
}

func TestAuthorization_TokenEndpoint_ShortVerifier(t *testing.T) {
	client := newTestClient()

	// Test with too short verifier
	data := url.Values{
		"grant":    {"code"},
		"code":     {"1234567890123456789012"},
		"verifier": {"short"},
		"redirect": {"http://example.com/callback"},
	}

	resp, err := postForm(client, "/auth/00000000-0000-7000-8000-000000000000/token", data, "")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for short verifier, got %d", resp.StatusCode)
	}
}

func TestAuthorization_TokenEndpoint_InvalidRedirect(t *testing.T) {
	client := newTestClient()

	// Test with invalid redirect
	data := url.Values{
		"grant":    {"code"},
		"code":     {"1234567890123456789012"},
		"verifier": {"12345678901234567890123456789012345678901234"},
		"redirect": {"not-a-url"},
	}

	resp, err := postForm(client, "/auth/00000000-0000-7000-8000-000000000000/token", data, "")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for invalid redirect, got %d", resp.StatusCode)
	}
}

func TestAuthorization_TokenEndpoint_InvalidUUID(t *testing.T) {
	client := newTestClient()

	// Test with invalid UUID
	data := url.Values{
		"grant":    {"code"},
		"code":     {"1234567890123456789012"},
		"verifier": {"12345678901234567890123456789012345678901234"},
		"redirect": {"http://example.com/callback"},
	}

	resp, err := postForm(client, "/auth/invalid-uuid/token", data, "")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for invalid UUID, got %d", resp.StatusCode)
	}
}

func TestAuthorization_TokenEndpoint_MissingFields(t *testing.T) {
	client := newTestClient()

	// Test with missing fields
	data := url.Values{
		"grant": {"code"},
	}

	resp, err := postForm(client, "/auth/00000000-0000-7000-8000-000000000000/token", data, "")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for missing fields, got %d", resp.StatusCode)
	}
}
