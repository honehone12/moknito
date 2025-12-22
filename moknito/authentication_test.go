package moknito

import (
	"context"
	"fmt"
	"moknito/id"
	"moknito/token"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
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

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected status 403 without auth cookie, got %d", resp.StatusCode)
	}
}

func TestAuthentication_InvalidAuthCookie_Malformed(t *testing.T) {
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
		{Name: "ae", Value: "this-is-not-a-jwt", Path: "/"},
	})

	// Try to access endpoint that requires authentication
	resp, err = postForm(client, "/api/app/00000000-0000-7000-8000-000000000000/allow", nil, testServer.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for invalid auth cookie, got %d", resp.StatusCode)
	}
}

func TestAuthentication_InvalidAuthCookie_Expired(t *testing.T) {
	client := newTestClient()
	ctx := context.Background()

	userID, _ := id.NewSequential()
	authID, _ := id.NewSequential()
	userEmail := fmt.Sprintf("expired-%s@example.com", uuid.NewString())
	testSystem.Ent().User.Create().SetID(string(userID)).SetName("u").SetEmail(userEmail).SetPwhash("p").SaveX(ctx)
	// Create an expired authentication
	testSystem.Ent().Authentication.Create().
		SetID(string(authID)).
		SetUserID(string(userID)).
		SetExpireAt(time.Now().Add(-time.Hour)).
		SetIP("127.0.0.1").SetUserAgent("test").
		SaveX(ctx)

	authUUID, _ := authID.ToUUID()
	userUUID, _ := userID.ToUUID()

	// Create a token that points to the expired auth record. The token itself is not expired yet.
	expiredToken, err := testSystem.AuthSigner().CreateAuthToken(token.CreateAuthTokenParams{
		Method:    jwt.SigningMethodHS256,
		TokenType: token.TOKEN_TYPE_AUTHENTICATION,
		AuthUuid:  authUUID,
		UserUuid:  userUUID,
		Ttl:       time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	serverURL, _ := url.Parse(testServer.URL)
	client.Jar.SetCookies(serverURL, []*http.Cookie{{Name: "ae", Value: expiredToken, Path: "/"}})

	resp, err := postForm(client, "/api/app/00000000-0000-7000-8000-000000000000/allow", nil, "")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// The system should find the token valid but the backing auth record expired.
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for expired auth record, got %d", resp.StatusCode)
	}
}

func TestAuthentication_InvalidAuthCookie_NoAuthRecord(t *testing.T) {
	client := newTestClient()

	// Create a token for an authentication ID that does not exist in the database.
	userID, _ := id.NewSequential()
	authID, _ := id.NewSequential() // This ID is not saved to the DB
	authUUID, _ := authID.ToUUID()
	userUUID, _ := userID.ToUUID()

	nonExistentToken, err := testSystem.AuthSigner().CreateAuthToken(token.CreateAuthTokenParams{
		Method:    jwt.SigningMethodHS256,
		TokenType: token.TOKEN_TYPE_AUTHENTICATION,
		AuthUuid:  authUUID,
		UserUuid:  userUUID,
		Ttl:       time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	serverURL, _ := url.Parse(testServer.URL)
	client.Jar.SetCookies(serverURL, []*http.Cookie{{Name: "ae", Value: nonExistentToken, Path: "/"}})

	resp, err := postForm(client, "/api/app/00000000-0000-7000-8000-000000000000/allow", nil, "")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for non-existent auth record, got %d", resp.StatusCode)
	}
}