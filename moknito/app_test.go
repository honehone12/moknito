package moknito

import (
	"context"
	"encoding/base64"
	"fmt"
	"moknito/ent/authentication"
	"moknito/ent/authorizedapp"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestApp_Allow_NoAuth(t *testing.T) {
	client := newTestClient()
	// Get session first to pass session check, but no auth
	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	resp.Body.Close()

	resp, err = postForm(client, "/api/app/00000000-0000-7000-8000-000000000000/allow", nil, testServer.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected status 403 without auth, got %d", resp.StatusCode)
	}
}

func TestApp_Authorize_NoAuth(t *testing.T) {
	client := newTestClient()
	// Get session first to pass session check, but no auth
	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	resp.Body.Close()

	resp, err = postForm(client, "/api/app/00000000-0000-7000-8000-000000000000/authorize", nil, testServer.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected status 403 without auth, got %d", resp.StatusCode)
	}
}

func TestApp_Allow_InvalidUUID(t *testing.T) {
	client, _ := newAuthenticatedTestClient(t)
	resp, err := postForm(client, "/api/app/invalid-uuid/allow", nil, testServer.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for invalid UUID, got %d", resp.StatusCode)
	}
}

func TestApp_Authorize_InvalidUUID(t *testing.T) {
	client, _ := newAuthenticatedTestClient(t)
	resp, err := postForm(client, "/api/app/invalid-uuid/authorize", nil, testServer.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for invalid UUID, got %d", resp.StatusCode)
	}
}

func TestApp_Flow_Success(t *testing.T) {
	client, ids := newAuthenticatedTestClient(t)
	ctx := context.Background()

	// 1. Allow the app
	resp, err := postForm(client, fmt.Sprintf("/api/app/%s/allow", ids.AppUUID), nil, "")
	if err != nil {
		t.Fatalf("allow request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200 for allow, got %d", resp.StatusCode)
	}

	// Verify in DB
	exists, err := testSystem.Ent().AuthorizedApp.Query().
		Where(authorizedapp.UserID(string(ids.UserID)), authorizedapp.ApplicationID(string(ids.AppID))).
		Exist(ctx)
	if err != nil || !exists {
		t.Fatal("authorized app was not created in db")
	}

	// 2. Authorize the app
	// The AppAuthorize sys call needs a challenge in Redis.
	auth, err := testSystem.Ent().Authentication.Query().Where(authentication.UserID(string(ids.UserID))).Only(ctx)
	if err != nil {
		t.Fatalf("could not find authentication for user: %v", err)
	}
	challengeKey := fmt.Sprintf("CHALL:%x:%x", ids.UserID, auth.ID)
	// The value stored in redis must be base64 encoded, as AppAuthorize decodes it.
	challengeStr := base64.RawURLEncoding.EncodeToString([]byte("a-valid-challenge-string"))
	err = testSystem.Redis().Set(ctx, challengeKey, challengeStr, time.Minute).Err()
	if err != nil {
		t.Fatalf("failed to set challenge in redis: %v", err)
	}

	resp, err = postForm(client, fmt.Sprintf("/api/app/%s/authorize", ids.AppUUID), nil, "")
	if err != nil {
		t.Fatalf("authorize request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("expected status 303 for authorize, got %d", resp.StatusCode)
	}

	locHeader := resp.Header.Get("Location")
	if !strings.HasPrefix(locHeader, ids.AppRedirect+"?code=") {
		t.Errorf("unexpected redirect location: got %s", locHeader)
	}
}

func TestApp_Authorize_NotAllowed(t *testing.T) {
	client, ids := newAuthenticatedTestClient(t)

	// Attempt to authorize without allowing first
	resp, err := postForm(client, fmt.Sprintf("/api/app/%s/authorize", ids.AppUUID), nil, "")
	if err != nil {
		t.Fatalf("authorize request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for authorizing not-allowed app, got %d", resp.StatusCode)
	}
}

func TestApp_Allow_NonExistentApp(t *testing.T) {
	client, _ := newAuthenticatedTestClient(t)
	nonExistentAppUUID := uuid.New().String()

	resp, err := postForm(client, fmt.Sprintf("/api/app/%s/allow", nonExistentAppUUID), nil, "")
	if err != nil {
		t.Fatalf("allow request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for allowing non-existent app, got %d", resp.StatusCode)
	}
}