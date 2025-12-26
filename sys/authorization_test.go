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
		TokenType:    token.TOKEN_TYPE_AUTHORIZATION,
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

func TestAuthorization_AuthRefresh(t *testing.T) {
	sys, _ := setupSys(t)
	defer sys.Close()
	ctx := context.Background()

	// 1. Setup Data
	appID, _ := binid.NewRandom()
	authID, _ := binid.NewRandom()
	userID, _ := binid.NewRandom()

	// Create App
	app, err := sys.ent.Application.Create().
		SetID(appID).
		SetDomain("example.com").
		SetRedirect("https://example.com/cb").
		SetName("Test App").
		Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Create User
	user, err := sys.ent.User.Create().
		SetID(userID).
		SetName("Test User").
		SetEmail("test@example.com").
		SetPwhash("hash").
		Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Create Authorization
	refreshExpireAt := time.Now().Add(time.Minute)
	auth, err := sys.ent.Authorization.Create().
		SetID(authID).
		SetUserID(user.ID).
		SetApplicationID(app.ID).
		SetCode([]byte("some-code")).
		SetChallenge([]byte("some-challenge")).
		SetChallengeMethod(challenge.CHALLENGE_METHOD_S256).
		SetExpireAt(time.Now().Add(time.Minute)).
		SetCodeExpireAt(time.Now().Add(time.Minute)).
		SetRefreshExpireAt(refreshExpireAt).
		Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Create a refresh token
	refTkn, err := sys.authSigner.CreateAuthToken(token.CreateAuthTokenParams{
		Method:       jwt.SigningMethodRS256,
		TokenType:    token.TOKEN_TYPE_REFRESH,
		AuthId:       auth.ID,
		UserId:       user.ID,
		Ttl:          time.Hour,
		Applications: []string{app.Domain},
	})
	if err != nil {
		t.Fatalf("Failed to create refresh token: %v", err)
	}

	// --- Success Case ---
	t.Run("Success", func(t *testing.T) {
		p := AuthRefreshParams{
			AuthParams: AuthParams{
				ApplicationId: appID,
			},
			Token: refTkn,
		}

		res := sys.AuthRefresh(ctx, p)

		if res.ValidationErr != nil {
			t.Fatalf("validation error: %v", res.ValidationErr)
		}
		if res.SystemErr != nil {
			t.Fatalf("system error: %v", res.SystemErr)
		}
		if res.Token == nil {
			t.Fatal("expected token, got nil")
		}
		if res.Domain != "example.com" {
			t.Errorf("expected domain example.com, got %s", res.Domain)
		}

		// Verify the new tokens
		claims, err := sys.authSigner.Parse(token.ParseParams{
			Raw:          res.Token.AccessToken,
			Method:       jwt.SigningMethodRS256,
			TokenType:    token.TOKEN_TYPE_AUTHORIZATION,
			Applications: []string{"example.com"},
		})
		if err != nil {
			t.Fatalf("Failed to parse new access token: %v", err)
		}
		if claims.Type != token.TOKEN_TYPE_AUTHORIZATION {
			t.Errorf("wrong access token type")
		}

		refreshClaims, err := sys.authSigner.Parse(token.ParseParams{
			Raw:          res.Token.RefreshToken,
			Method:       jwt.SigningMethodRS256,
			TokenType:    token.TOKEN_TYPE_REFRESH,
			Applications: []string{"example.com"},
		})
		if err != nil {
			t.Fatalf("Failed to parse new refresh token: %v", err)
		}
		if refreshClaims.Type != token.TOKEN_TYPE_REFRESH {
			t.Errorf("wrong refresh token type")
		}

		// Verify DB update
		updatedAuth, err := sys.ent.Authorization.Get(ctx, authID)
		if err != nil {
			t.Fatalf("failed to get updated authorization: %v", err)
		}
		if updatedAuth.RefreshExpireAt.Equal(refreshExpireAt) {
			t.Error("refresh expire at was not updated")
		}
	})

	// --- Failure Cases ---
	t.Run("Failure cases", func(t *testing.T) {
		// Create a separate authorization for expired test
		expiredAuthID, _ := binid.NewRandom()
		_, err := sys.ent.Authorization.Create().
			SetID(expiredAuthID).
			SetUserID(user.ID).
			SetApplicationID(app.ID).
			SetCode([]byte("expired-code")).
			SetChallenge([]byte("some-challenge")).
			SetChallengeMethod(challenge.CHALLENGE_METHOD_S256).
			SetExpireAt(time.Now().Add(-time.Minute)).
			SetCodeExpireAt(time.Now().Add(-time.Minute)).
			SetRefreshExpireAt(time.Now().Add(-time.Minute)). // expired
			Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		expiredRefTkn, err := sys.authSigner.CreateAuthToken(token.CreateAuthTokenParams{
			Method:       jwt.SigningMethodRS256,
			TokenType:    token.TOKEN_TYPE_REFRESH,
			AuthId:       expiredAuthID,
			UserId:       user.ID,
			Ttl:          -time.Minute, // expired
			Applications: []string{app.Domain},
		})
		if err != nil {
			t.Fatalf("Failed to create expired refresh token: %v", err)
		}

		// Wrong token type
		wrongTypeToken, err := sys.authSigner.CreateAuthToken(token.CreateAuthTokenParams{
			Method:       jwt.SigningMethodRS256,
			TokenType:    token.TOKEN_TYPE_AUTHORIZATION, // this is not a refresh token
			AuthId:       authID,
			UserId:       user.ID,
			Ttl:          time.Minute,
			Applications: []string{app.Domain},
		})
		if err != nil {
			t.Fatalf("failed to create wrong type token: %v", err)
		}

		// Another app for testing wrong app case
		otherAppID, _ := binid.NewRandom()
		_, err = sys.ent.Application.Create().
			SetID(otherAppID).
			SetDomain("otherapp.com").
			SetRedirect("https://otherapp.com/cb").
			SetName("Other App").
			Save(ctx)
		if err != nil {
			t.Fatal(err)
		}

		testCases := []struct {
			name   string
			params AuthRefreshParams
		}{
			{
				name: "Expired Token",
				params: AuthRefreshParams{
					AuthParams: AuthParams{ApplicationId: appID},
					Token:      expiredRefTkn,
				},
			},
			{
				name: "Invalid Token String",
				params: AuthRefreshParams{
					AuthParams: AuthParams{ApplicationId: appID},
					Token:      "this.is.not.a.jwt",
				},
			},
			{
				name: "Wrong Token Type",
				params: AuthRefreshParams{
					AuthParams: AuthParams{ApplicationId: appID},
					Token:      wrongTypeToken,
				},
			},
			{
				name: "Wrong Application",
				params: AuthRefreshParams{
					AuthParams: AuthParams{ApplicationId: otherAppID}, // Using other app's ID
					Token:      refTkn,
				},
			},
			{
				name: "Non-existent Authorization",
				params: AuthRefreshParams{
					AuthParams: AuthParams{ApplicationId: appID},
					Token: func() string {
						// Create a token for an auth ID that does not exist
						nonExistentAuthID, _ := binid.NewRandom()
						tkn, _ := sys.authSigner.CreateAuthToken(token.CreateAuthTokenParams{
							Method:       jwt.SigningMethodRS256,
							TokenType:    token.TOKEN_TYPE_REFRESH,
							AuthId:       nonExistentAuthID,
							UserId:       user.ID,
							Ttl:          time.Minute,
							Applications: []string{app.Domain},
						})
						return tkn
					}(),
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				res := sys.AuthRefresh(ctx, tc.params)
				if res.ValidationErr == nil {
					t.Errorf("expected validation error, got nil")
				}
			})
		}
	})
}
