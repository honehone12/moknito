package moknito

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"moknito/binid"
	"moknito/challenge"
	"moknito/token"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestAuthorization_TokenEndpoint_Validation(t *testing.T) {
	client := newTestClient()
	appID, _ := binid.NewSequential()

	testCases := []struct {
		name       string
		data       url.Values
		pathParam  string
		expectCode int
	}{
		{
			name:       "Invalid Grant",
			data:       url.Values{"grant": {"invalid_grant"}},
			pathParam:  appID.String(),
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "Short Code",
			data:       url.Values{"grant": {"code"}, "code": {"short"}},
			pathParam:  appID.String(),
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "Short Verifier",
			data:       url.Values{"grant": {"code"}, "verifier": {"short"}},
			pathParam:  appID.String(),
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "Invalid Redirect URL",
			data:       url.Values{"grant": {"code"}, "redirect": {"not-a-url"}},
			pathParam:  appID.String(),
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "Invalid UUID",
			data:       url.Values{"grant": {"code"}},
			pathParam:  "invalid-uuid",
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "Missing Fields",
			data:       url.Values{"grant": {"code"}},
			pathParam:  appID.String(),
			expectCode: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Grant type "code" requires session and origin guard, but we are testing validation before that.
			// However, some routes might have middleware that runs first. For /auth, it's public.
			path := fmt.Sprintf("/auth/%s/token", tc.pathParam)
			resp, err := postForm(client, path, tc.data, "")
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

func TestAuthorization_TokenEndpoint_Flow(t *testing.T) {
	client := newTestClient()
	ctx := context.Background()

	// 1. Setup entities
	_, ids := newAuthenticatedTestClient(t)

	// 2. Setup Authorization Code
	codeRaw := []byte("a-secret-code-16") // 16 bytes
	codeStr := base64.RawURLEncoding.EncodeToString(codeRaw)
	verifierRaw := []byte("a-long-verifier-string-to-be-hashed")
	verifierStr := base64.RawURLEncoding.EncodeToString(verifierRaw)
	challengeHashed := sha256.Sum256(verifierRaw)
	authID, _ := binid.NewSequential()

	_, err := testSystem.Ent().Authorization.Create().
		SetID(authID).
		SetUserID(ids.UserID).
		SetApplicationID(ids.AppID).
		SetCode(codeRaw).
		SetChallenge(challengeHashed[:]).
		SetChallengeMethod(challenge.CHALLENGE_METHOD_S256).
		SetExpireAt(time.Now().Add(time.Minute)).
		SetCodeExpireAt(time.Now().Add(time.Minute)).
		SetRefreshExpireAt(time.Now().Add(time.Minute)).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create authorization record: %v", err)
	}

	// --- Success Case ---
	t.Run("Success", func(t *testing.T) {
		data := url.Values{
			"grant":    {"code"},
			"code":     {codeStr},
			"verifier": {verifierStr},
			"redirect": {ids.AppRedirect},
		}

		path := fmt.Sprintf("/auth/%s/token", ids.AppUUID)
		resp, err := postForm(client, path, data, ids.AppRedirect)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d. body: %s", resp.StatusCode, string(body))
		}

		var tokenResp token.AuthTokenBundle
		if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
			t.Fatalf("failed to decode token response: %v", err)
		}
		if tokenResp.AccessToken == "" {
			t.Error("access token is empty")
		}
		if tokenResp.BundleTokenType != token.BUNDLE_TOKEN_TYPE_BEARER {
			t.Errorf("unexpected token type: %s", tokenResp.BundleTokenType)
		}
	})

	// --- Code Reuse Case ---
	t.Run("Code Reuse", func(t *testing.T) {
		data := url.Values{
			"grant":    {"code"},
			"code":     {codeStr},
			"verifier": {verifierStr},
			"redirect": {ids.AppRedirect},
		}

		path := fmt.Sprintf("/auth/%s/token", ids.AppUUID)
		resp, err := postForm(client, path, data, ids.AppRedirect)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		// The code was already consumed in the success case
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected status 400 for code reuse, got %d", resp.StatusCode)
		}
	})
}

func TestAuthorization_TokenEndpoint_InvalidLogic(t *testing.T) {
	client := newTestClient()
	ctx := context.Background()

	// 1. Setup entities
	_, ids := newAuthenticatedTestClient(t)

	// 2. Setup Authorization Code
	codeRaw := []byte("another-code-sec") // 16 bytes
	codeStr := base64.RawURLEncoding.EncodeToString(codeRaw)
	expiredCodeRaw := []byte("expired-code-123") // 16 bytes
	expiredCodeStr := base64.RawURLEncoding.EncodeToString(expiredCodeRaw)

	verifierRaw := []byte("a-long-verifier-string-to-be-hashed")
	verifierStr := base64.RawURLEncoding.EncodeToString(verifierRaw)
	wrongVerifierStr := base64.RawURLEncoding.EncodeToString([]byte("this-is-the-wrong-verifier"))
	challengeHashed := sha256.Sum256(verifierRaw)
	authID, _ := binid.NewSequential()
	expiredAuthID, _ := binid.NewSequential()

	// Create a valid authorization record
	_, err := testSystem.Ent().Authorization.Create().
		SetID(authID).
		SetUserID(ids.UserID).
		SetApplicationID(ids.AppID).
		SetCode(codeRaw).
		SetChallenge(challengeHashed[:]).
		SetChallengeMethod(challenge.CHALLENGE_METHOD_S256).
		SetExpireAt(time.Now().Add(time.Minute)).
		SetCodeExpireAt(time.Now().Add(time.Minute)).
		SetRefreshExpireAt(time.Now().Add(time.Minute)).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create authorization record: %v", err)
	}
	// Create an expired authorization record
	_, err = testSystem.Ent().Authorization.Create().
		SetID(expiredAuthID).
		SetUserID(ids.UserID).
		SetApplicationID(ids.AppID).
		SetCode(expiredCodeRaw).
		SetChallenge(challengeHashed[:]).
		SetChallengeMethod(challenge.CHALLENGE_METHOD_S256).
		SetExpireAt(time.Now().Add(time.Minute)).
		SetCodeExpireAt(time.Now().Add(-time.Minute)). // Expired
		SetRefreshExpireAt(time.Now().Add(time.Minute)).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create expired authorization record: %v", err)
	}

	testCases := []struct {
		name string
		data url.Values
	}{
		{
			name: "Wrong Verifier",
			data: url.Values{
				"grant": {"code"}, "code": {codeStr}, "verifier": {wrongVerifierStr}, "redirect": {ids.AppRedirect},
			},
		},
		{
			name: "Wrong Redirect",
			data: url.Values{
				"grant": {"code"}, "code": {codeStr}, "verifier": {verifierStr}, "redirect": {"http://evil.com/cb"},
			},
		},
		{
			name: "Expired Code",
			data: url.Values{
				"grant": {"code"}, "code": {expiredCodeStr}, "verifier": {verifierStr}, "redirect": {ids.AppRedirect},
			},
		},
		{
			name: "Non-existent Code",
			data: url.Values{
				"grant": {"code"}, "code": {base64.RawURLEncoding.EncodeToString([]byte("fake-code-16-byte"))}, "verifier": {verifierStr}, "redirect": {ids.AppRedirect},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			path := fmt.Sprintf("/auth/%s/token", ids.AppUUID)
			resp, err := postForm(client, path, tc.data, ids.AppRedirect)
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
