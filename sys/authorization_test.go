package sys

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"moknito/binid"
	"moknito/challenge"
	"moknito/token"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestAuthorization_AuthTokenCode(t *testing.T) {
	sys, _ := setupSys(t)
	defer sys.Close()
	ctx := context.Background()

	// 1. Setup Data
	appID, _ := binid.NewRandom()
	authID, _ := binid.NewRandom()
	userID, _ := binid.NewRandom()

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
		SetID(appID).
		SetDomain("example.com").
		SetRedirect("https://example.com/cb").
		SetName("Test App").
		Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Create User
	_, err = sys.ent.User.Create().
		SetID(userID).
		SetName("Test User").
		SetEmail("test@example.com").
		SetPwhash("hash").
		Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Create Authorization
	_, err = sys.ent.Authorization.Create().
		SetID(authID).
		SetUserID(userID).
		SetApplicationID(appID).SetCode(codeRaw).
		SetChallenge(challengeBytes).
		SetChallengeMethod(challenge.CHALLENGE_METHOD_S256).
		SetExpireAt(time.Now().Add(time.Minute)).
		SetCodeExpireAt(time.Now().Add(time.Minute)).
		SetRefreshExpireAt(time.Now().Add(time.Minute)).
		Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Execute Test
	p := AuthTokenParams{
		AuthParams: AuthParams{
			ApplicationId: appID,
		},
		Code:     codeStr,
		Verifier: verifierStr,
		Redirect: "https://example.com/cb",
	}

	res := sys.AuthToken(ctx, p)

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

	// Verify the token signature
	claims, err := sys.authSigner.Parse(token.ParseParams{
		Raw:          res.Token.AccessToken,
		Method:       jwt.SigningMethodRS256,
		Applications: []string{"example.com"},
	})
	if err != nil {
		t.Fatalf("Failed to parse access token: %v", err)
	}
	if claims.Type != token.TOKEN_TYPE_AUTHORIZATION {
		t.Errorf("wrong token type")
	}

	// 3. Verify Code is Consumed (Double use check)
	res2 := sys.AuthToken(ctx, p)
	if res2.ValidationErr == nil {
		t.Error("expected error for reused code, got nil")
	}
}
