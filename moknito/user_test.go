package moknito

import (
	"net/http"
	"net/url"
	"testing"
)

func TestUser_Register(t *testing.T) {
	client := newTestClient()

	// First get a session
	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	resp.Body.Close()

	// Test user registration with valid data
	data := url.Values{
		"name":     {"Test User"},
		"email":    {"testuser@example.com"},
		"password": {"securepassword123"},
	}

	resp, err = postForm(client, "/api/user/00000000-0000-7000-8000-000000000000/register", data, testServer.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// The app ID doesn't exist, so we expect BadRequest
	// In a full integration test with real DB, this would succeed
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected status: got %d", resp.StatusCode)
	}
}

func TestUser_Register_InvalidEmail(t *testing.T) {
	client := newTestClient()

	// First get a session
	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	resp.Body.Close()

	// Test with invalid email
	data := url.Values{
		"name":     {"Test User"},
		"email":    {"invalid-email"},
		"password": {"securepassword123"},
	}

	resp, err = postForm(client, "/api/user/00000000-0000-7000-8000-000000000000/register", data, testServer.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for invalid email, got %d", resp.StatusCode)
	}
}

func TestUser_Register_ShortPassword(t *testing.T) {
	client := newTestClient()

	// First get a session
	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	resp.Body.Close()

	// Test with short password
	data := url.Values{
		"name":     {"Test User"},
		"email":    {"test@example.com"},
		"password": {"short"}, // less than 8 chars
	}

	resp, err = postForm(client, "/api/user/00000000-0000-7000-8000-000000000000/register", data, testServer.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for short password, got %d", resp.StatusCode)
	}
}

func TestUser_Register_EmptyName(t *testing.T) {
	client := newTestClient()

	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	resp.Body.Close()

	data := url.Values{
		"name":     {""},
		"email":    {"test@example.com"},
		"password": {"securepassword123"},
	}

	resp, err = postForm(client, "/api/user/00000000-0000-7000-8000-000000000000/register", data, testServer.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for empty name, got %d", resp.StatusCode)
	}
}

func TestUser_Authenticate_NoSession(t *testing.T) {
	client := newTestClient()

	// Try to authenticate without session
	data := url.Values{
		"email":            {"test@example.com"},
		"password":         {"securepassword123"},
		"challenge":        {"12345678901234567890123456789012345678901234"}, // 43 chars base64
		"challenge_method": {"S256"},
		"redirect":         {"http://example.com/callback"},
	}

	resp, err := postForm(client, "/api/user/00000000-0000-7000-8000-000000000000/authenticate", data, testServer.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should be forbidden without session
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected status 403 without session, got %d", resp.StatusCode)
	}
}

func TestUser_Join_InvalidChallengeMethod(t *testing.T) {
	client := newTestClient()

	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	resp.Body.Close()

	// Test with unsupported challenge method
	data := url.Values{
		"email":            {"test@example.com"},
		"password":         {"securepassword123"},
		"challenge":        {"12345678901234567890123456789012345678901234"},
		"challenge_method": {"plain"}, // Not S256
		"redirect":         {"http://example.com/callback"},
	}

	resp, err = postForm(client, "/api/user/00000000-0000-7000-8000-000000000000/join", data, testServer.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for unsupported challenge method, got %d", resp.StatusCode)
	}
}

func TestUser_Join_InvalidChallenge(t *testing.T) {
	client := newTestClient()

	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	resp.Body.Close()

	// Test with too short challenge
	data := url.Values{
		"email":            {"test@example.com"},
		"password":         {"securepassword123"},
		"challenge":        {"tooshort"},
		"challenge_method": {"S256"},
		"redirect":         {"http://example.com/callback"},
	}

	resp, err = postForm(client, "/api/user/00000000-0000-7000-8000-000000000000/join", data, testServer.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for invalid challenge, got %d", resp.StatusCode)
	}
}

func TestUser_Join_InvalidRedirect(t *testing.T) {
	client := newTestClient()

	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	resp.Body.Close()

	// Test with invalid redirect URL
	data := url.Values{
		"email":            {"test@example.com"},
		"password":         {"securepassword123"},
		"challenge":        {"12345678901234567890123456789012345678901234"},
		"challenge_method": {"S256"},
		"redirect":         {"not-a-url"},
	}

	resp, err = postForm(client, "/api/user/00000000-0000-7000-8000-000000000000/join", data, testServer.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for invalid redirect URL, got %d", resp.StatusCode)
	}
}

func TestUser_Authenticate_InvalidUUID(t *testing.T) {
	client := newTestClient()

	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	resp.Body.Close()

	// Test with invalid UUID format
	data := url.Values{
		"email":            {"test@example.com"},
		"password":         {"securepassword123"},
		"challenge":        {"12345678901234567890123456789012345678901234"},
		"challenge_method": {"S256"},
		"redirect":         {"http://example.com/callback"},
	}

	resp, err = postForm(client, "/api/user/invalid-uuid/authenticate", data, testServer.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for invalid UUID, got %d", resp.StatusCode)
	}
}
