package moknito

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestUser_E2E_Register_Join_Authenticate(t *testing.T) {
	// 1. Register and Join is handled by the helper
	client, ids := newAuthenticatedTestClient(t)

	// 2. Authenticate with correct credentials
	// Get a new session for a clean test
	client = newTestClient()
	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	resp.Body.Close()

	authData := url.Values{
		"email":            {ids.UserEmail},
		"password":         {ids.UserPass},
		"challenge":        {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		"challenge_method": {"S256"},
		"redirect":         {ids.AppRedirect},
	}
	resp, err = postForm(client, "/api/user/"+ids.AppUUID+"/authenticate", authData, testServer.URL)
	if err != nil {
		t.Fatalf("authentication request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200 for authentication, got %d", resp.StatusCode)
	}
	if findCookie(resp.Cookies(), "ae") == nil {
		t.Error("auth cookie 'ae' was not set on authentication")
	}
}

func TestUser_Register_Validation(t *testing.T) {
	client := newTestClient()
	_, ids := newAuthenticatedTestClient(t) // To get a valid app context

	// Get a session
	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	resp.Body.Close()

	testCases := []struct {
		name string
		data url.Values
	}{
		{"Invalid Email", url.Values{"name": {"Test"}, "email": {"invalid"}, "password": {"password123"}}},
		{"Short Password", url.Values{"name": {"Test"}, "email": {"test@example.com"}, "password": {"short"}}},
		{"Empty Name", url.Values{"name": {""}, "email": {"test@example.com"}, "password": {"password123"}}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := postForm(client, "/api/user/"+ids.AppUUID+"/register", tc.data, testServer.URL)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("expected status 400, got %d", resp.StatusCode)
			}
		})
	}
}

func TestUser_Join_And_Auth_Invalid(t *testing.T) {
	client := newTestClient()
	_, ids := newAuthenticatedTestClient(t) // Creates user and app context

	// Get a new session
	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	resp.Body.Close()

	testCases := []struct {
		name     string
		endpoint string
		data     url.Values
	}{
		{"Unsupported Challenge Method", "/join", url.Values{"challenge_method": {"plain"}}},
		{"Invalid Challenge", "/join", url.Values{"challenge": {"short"}}},
		{"Invalid Redirect", "/join", url.Values{"redirect": {"not-a-url"}}},
		{"Invalid UUID", "/authenticate", url.Values{}},
	}

	baseData := url.Values{
		"email":            {ids.UserEmail},
		"password":         {ids.UserPass},
		"challenge":        {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		"challenge_method": {"S256"},
		"redirect":         {ids.AppRedirect},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := make(url.Values)
			for k, v := range baseData {
				data[k] = v
			}
			for k, v := range tc.data {
				data[k] = v
			}

			path := "/api/user/" + ids.AppUUID + tc.endpoint
			if strings.Contains(tc.name, "UUID") {
				path = "/api/user/invalid-uuid" + tc.endpoint
			}

			resp, err := postForm(client, path, data, testServer.URL)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("expected status 400, got %d", resp.StatusCode)
			}
		})
	}
}

func TestUser_Duplicate_And_Lockout(t *testing.T) {
	client := newTestClient()
	_, ids := newAuthenticatedTestClient(t) // Creates first user

	ctx := context.Background()

	// Get a session
	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	resp.Body.Close()

	// --- Duplicate Registration ---
	t.Run("Duplicate Registration", func(t *testing.T) {
		regData := url.Values{
			"name":     {"Another User"},
			"email":    {ids.UserEmail}, // Same email
			"password": {"another-password"},
		}
		resp, err := postForm(client, "/api/user/"+ids.AppUUID+"/register", regData, testServer.URL)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		// sys.UserRegister returns a validation error for duplicate users
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected status 400 for duplicate registration, got %d", resp.StatusCode)
		}
	})

	// --- Wrong Password and Lockout ---
	t.Run("Wrong Password and Lockout", func(t *testing.T) {
		// Try to authenticate with wrong password multiple times
		authData := url.Values{
			"email":            {ids.UserEmail},
			"password":         {"wrong-password"},
			"challenge":        {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
			"challenge_method": {"S256"},
			"redirect":         {ids.AppRedirect},
		}

		// AUTHENTICATION_MAX_ERROR is 10 in sys
		for i := 0; i < 11; i++ {
			resp, err := postForm(client, "/api/user/"+ids.AppUUID+"/authenticate", authData, testServer.URL)
			if err != nil {
				t.Fatalf("auth request failed: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("iteration %d: expected status 400, got %d", i, resp.StatusCode)
			}
		}

		// The 12th attempt should fail because user is locked
		resp, err := postForm(client, "/api/user/"+ids.AppUUID+"/authenticate", authData, testServer.URL)
		if err != nil {
			t.Fatalf("auth request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected status 400 for locked user, got %d", resp.StatusCode)
		}

		// Verify error count in Redis
		errKey := fmt.Sprintf("ERROR:%s", ids.UserEmail)
		val, err := testSystem.Redis().Get(ctx, errKey).Result()
		if err != nil {
			t.Fatalf("failed to get error count from redis: %v", err)
		}
		count, _ := strconv.Atoi(val)
		if count <= 10 {
			t.Errorf("expected error count > 10, got %d", count)
		}
	})
}