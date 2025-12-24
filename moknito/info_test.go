package moknito

import (
	"context"
	"encoding/json"
	"fmt"
	"moknito/binid"
	"net/http"
	"testing"
)

func TestInfo_NoAuth(t *testing.T) {
	client := newTestClient()

	// First get a session to pass the session middleware
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

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected status 403 without auth, got %d", resp.StatusCode)
	}
}

func TestInfo_Success(t *testing.T) {
	client, ids := newAuthenticatedTestClient(t)

	path := fmt.Sprintf("/info/%s", ids.AppUUID)
	resp, err := getRequest(client, path)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var info InfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	app, err := testSystem.Ent().Application.Get(context.Background(), ids.AppID)
	if err != nil {
		t.Fatalf("failed to get app from db: %v", err)
	}

	if info.Name != app.Name {
		t.Errorf("expected name %s, got %s", app.Name, info.Name)
	}
	if info.Domain != app.Domain {
		t.Errorf("expected domain %s, got %s", app.Domain, info.Domain)
	}
}

func TestInfo_NonExistentApp(t *testing.T) {
	client, _ := newAuthenticatedTestClient(t)
	appID, _ := binid.NewSequential()

	path := fmt.Sprintf("/info/%s", appID.String())
	resp, err := getRequest(client, path)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for non-existent app, got %d", resp.StatusCode)
	}
}

func TestInfo_InvalidUUID(t *testing.T) {
	client, _ := newAuthenticatedTestClient(t)

	resp, err := getRequest(client, "/info/invalid-uuid")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for invalid uuid, got %d", resp.StatusCode)
	}
}
