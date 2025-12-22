package moknito

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"
)

func TestOrigin_OriginGuard(t *testing.T) {
	client := newTestClient()
	_, ids := newAuthenticatedTestClient(t) // Creates a valid app

	// Get a session first, as it's required by the user group
	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	resp.Body.Close()

	testCases := []struct {
		name       string
		origin     string
		email      string
		expectCode int
	}{
		{
			name:       "No Origin Header",
			origin:     "",
			email:      fmt.Sprintf("test-%s@example.com", uuid.NewString()),
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "Wrong Origin Header",
			origin:     "http://evil.com",
			email:      fmt.Sprintf("test-%s@example.com", uuid.NewString()),
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "Correct Origin Header",
			origin:     testServer.URL,
			email:      fmt.Sprintf("test-%s@example.com", uuid.NewString()),
			expectCode: http.StatusOK, // Should now succeed
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := url.Values{
				"name":     {"Test"},
				"email":    {tc.email},
				"password": {"password123"},
			}
			// Use the valid app UUID created by the helper
			resp, err := postForm(client, "/api/user/"+ids.AppUUID+"/register", data, tc.origin)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.expectCode {
				t.Errorf("expected status %d, got %d", tc.expectCode, resp.StatusCode)
			}
		})
	}
}
