package sys

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"moknito/challenge"
	"moknito/id"
	"testing"
	"time"
)

func TestAuthorization_AuthTokenCode(t *testing.T) {
	sys, _ := setupSys(t)
	defer sys.Close()
	ctx := context.Background()

	// 1. Setup Data
	appID, _ := id.NewRandom()
	authID, _ := id.NewRandom()
	userID, _ := id.NewRandom()

	// Challenge/Verifier logic:
	// Verifier: "secret". 
	verifierRaw := []byte("my-verifier-secret")
	// Params.Verifier is base64 encoded
	verifierStr := base64.RawURLEncoding.EncodeToString(verifierRaw)

	// DB Challenge is SHA256(verifierRaw)
	h := sha256.Sum256(verifierRaw)
	challengeBytes := h[:]

	// Code: "code"
	codeRaw := []byte("my-auth-code")
	// Params.Code is base64 encoded
	codeStr := base64.RawURLEncoding.EncodeToString(codeRaw)

	// Create App
	_, err := sys.ent.Application.Create().
		SetID(string(appID)).
		SetDomain("example.com").
		SetRedirect("https://example.com/cb").
		SetName("Test App").
		Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Create User
	_, err = sys.ent.User.Create().
		SetID(string(userID)).
		SetName("Test User").
		SetEmail("test@example.com").
		SetPwhash("hash").
		Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Create Authorization
	_, err = sys.ent.Authorization.Create().
		SetID(string(authID)).
		SetUserID(string(userID)).
		SetApplicationID(string(appID)).
		SetCode(codeRaw).
		SetChallenge(challengeBytes).
		SetChallengeMethod(challenge.CHALLENGE_METHOD_S256).
		SetExpireAt(time.Now().Add(time.Minute)).
		SetCodeExpireAt(time.Now().Add(time.Minute)).
		Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Execute Test
	p := AuthTokenCodeParams{
		AuthTokenParams: AuthTokenParams{
			ApplicationId: appID,
		},
		Code:     codeStr,
		Verifier: verifierStr,
		Redirect: "https://example.com/cb",
	}

	res := sys.AuthTokenCode(ctx, p)

	if res.ValidationErr != nil {
		t.Errorf("validation error: %v", res.ValidationErr)
	}
	if res.SystemErr != nil {
		t.Errorf("system error: %v", res.SystemErr)
	}
	if res.Token == nil {
		t.Fatal("expected token, got nil")
	}
	if res.Domain != "example.com" {
		t.Errorf("expected domain example.com, got %s", res.Domain)
	}

	// 3. Verify Code is Consumed (Double use check)
	res2 := sys.AuthTokenCode(ctx, p)
	if res2.ValidationErr == nil {
		t.Error("expected error for reused code, got nil")
	}
}
