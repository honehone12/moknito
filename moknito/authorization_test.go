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

	"github.com/golang-jwt/jwt/v5"
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
	wrongVerifierStr := base64.RawURLEncoding.EncodeToString([]byte("cccccccccccccccccccccccccccccccc"))
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
				"grant": {"code"}, "code": {base64.RawURLEncoding.EncodeToString([]byte("fake-code-16byte"))}, "verifier": {verifierStr}, "redirect": {ids.AppRedirect},
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

func TestAuthorization_RefreshEndpoint_Validation(t *testing.T) {
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
			name:       "Not a JWT token",
			data:       url.Values{"grant": {"refresh"}, "token": {"not-a-jwt"}},
			pathParam:  appID.String(),
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "Invalid UUID",
			data:       url.Values{"grant": {"refresh"}},
			pathParam:  "invalid-uuid",
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "Missing Fields",
			data:       url.Values{"grant": {"refresh"}},
			pathParam:  appID.String(),
			expectCode: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			path := fmt.Sprintf("/auth/%s/refresh", tc.pathParam)
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

func TestAuthorization_RefreshEndpoint_Flow(t *testing.T) {
	client := newTestClient()
	ctx := context.Background()

	// 1. Setup entities
	_, ids := newAuthenticatedTestClient(t)

	// 2. Setup Authorization Code to get an initial token
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
		SetRefreshExpireAt(time.Now().Add(time.Hour)). // Long refresh time
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create authorization record: %v", err)
	}

	// 3. Get initial token bundle
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

	var initialTokenResp token.AuthTokenBundle
	if err := json.NewDecoder(resp.Body).Decode(&initialTokenResp); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}
	if initialTokenResp.RefreshToken == "" {
		t.Fatal("refresh token is empty")
	}

	// --- Success Case ---
	t.Run("Success", func(t *testing.T) {
		// Introduce a small delay to ensure the new token's 'iat' is different
		time.Sleep(1 * time.Second)

		refreshData := url.Values{
			"grant": {"refresh"},
			"token": {initialTokenResp.RefreshToken},
		}

		refreshPath := fmt.Sprintf("/auth/%s/refresh", ids.AppUUID)
		refreshResp, err := postForm(client, refreshPath, refreshData, ids.AppRedirect)
		if err != nil {
			t.Fatalf("refresh request failed: %v", err)
		}
		defer refreshResp.Body.Close()

		if refreshResp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(refreshResp.Body)
			t.Fatalf("expected status 200, got %d. body: %s", refreshResp.StatusCode, string(body))
		}

		var refreshedTokenResp token.AuthTokenBundle
		if err := json.NewDecoder(refreshResp.Body).Decode(&refreshedTokenResp); err != nil {
			t.Fatalf("failed to decode refreshed token response: %v", err)
		}
		if refreshedTokenResp.AccessToken == "" {
			t.Error("refreshed access token is empty")
		}
		if refreshedTokenResp.RefreshToken == "" {
			t.Error("refreshed refresh token is empty")
		}
		if refreshedTokenResp.AccessToken == initialTokenResp.AccessToken {
			t.Error("access token was not refreshed")
		}
		if refreshedTokenResp.RefreshToken == initialTokenResp.RefreshToken {
			t.Error("refresh token was not rotated")
		}
	})

	// --- Invalid Logic Case ---
	t.Run("Expired Token", func(t *testing.T) {
		// Create expired token
		expiredAuthID, _ := binid.NewSequential()
		_, err := testSystem.Ent().Authorization.Create().
			SetID(expiredAuthID).
			SetUserID(ids.UserID).
			SetApplicationID(ids.AppID).
			SetCode([]byte("1234567890123456")).
			SetChallenge([]byte("01234567890123456789012345678901")).
			SetChallengeMethod(challenge.CHALLENGE_METHOD_S256).
			SetExpireAt(time.Now().Add(-time.Minute)).
			SetCodeExpireAt(time.Now().Add(-time.Minute)).
			SetRefreshExpireAt(time.Now().Add(-time.Minute)). // Expired
			Save(ctx)
		if err != nil {
			t.Fatalf("failed to create expired authorization record: %v", err)
		}
		app, err := testSystem.Ent().Application.Get(ctx, ids.AppID)
		if err != nil {
			t.Fatal(err)
		}
		expiredToken, err := testSystem.AuthSigner().CreateAuthToken(token.CreateAuthTokenParams{
			Method:       jwt.SigningMethodRS256,
			TokenType:    token.TOKEN_TYPE_REFRESH,
			AuthId:       expiredAuthID,
			UserId:       ids.UserID,
			Ttl:          -time.Minute,
			Applications: []string{app.Domain},
		})
		if err != nil {
			t.Fatal(err)
		}

		refreshData := url.Values{
			"grant": {"refresh"},
			"token": {expiredToken},
		}

		refreshPath := fmt.Sprintf("/auth/%s/refresh", ids.AppUUID)
		refreshResp, err := postForm(client, refreshPath, refreshData, ids.AppRedirect)
		if err != nil {
			t.Fatalf("refresh request failed: %v", err)
		}
		defer refreshResp.Body.Close()

		if refreshResp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected status 400 for expired token, got %d", refreshResp.StatusCode)
		}
	})
}
