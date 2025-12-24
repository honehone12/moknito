package sys

import (
	"context"
	"fmt"
	"moknito/binid"
	"moknito/hash"
	"testing"
)

func TestUser_RegisterAndJoin(t *testing.T) {
	sys, _ := setupSys(t)
	defer sys.Close()
	ctx := context.Background()

	// 1. Setup Data
	email := "test@example.com"
	password := "password123"
	appName := "TestApp"
	appID, _ := binid.NewRandom()

	_, err := sys.ent.Application.Create().
		SetID(appID).
		SetName(appName).
		SetDomain("example.com").
		SetRedirect("https://example.com/cb").
		Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// 2. UserRegister
	regRes := sys.UserRegister(ctx, UserRegisterParams{
		Name:     "Test User",
		Email:    email,
		Password: password,
	})
	if regRes.ValidationErr != nil {
		t.Fatalf("Register validation error: %v", regRes.ValidationErr)
	}
	if regRes.SystemErr != nil {
		t.Fatalf("Register system error: %v", regRes.SystemErr)
	}

	// 3. UserJoin
	// Helper to check errors
	checkJoin := func(p UserJoinParams, wantErr bool) *UserJoinResult {
		r := sys.UserJoin(ctx, p)
		if wantErr {
			if r.ValidationErr == nil && r.SystemErr == nil {
				t.Error("expected error for UserJoin, got nil")
			}
		} else {
			if r.ValidationErr != nil {
				t.Errorf("UserJoin val error: %v", r.ValidationErr)
			}
			if r.SystemErr != nil {
				t.Errorf("UserJoin sys error: %v", r.SystemErr)
			}
		}
		return r
	}

	// Case: Wrong Password
	checkJoin(UserJoinParams{
		ApplicationId: appID,
		Email:         email,
		Password:      "wrongpass",
		Redirect:      "https://example.com/cb",
	}, true)

	// Case: Success
	res := checkJoin(UserJoinParams{
		ApplicationId: appID,
		Email:         email,
		Password:      password,
		Redirect:      "https://example.com/cb",
		Ip:            "1.2.3.4",
		UserAgent:     "GoTest",
		Challenge:     "challenge123",
	}, false)

	if res.Cookie == nil {
		t.Fatal("expected cookie after join")
	}

	// Verify User in Ent
	exists, _ := sys.ent.User.Query().Exist(ctx)
	if !exists {
		t.Error("User not created in DB")
	}
}

func TestUser_Authenticate(t *testing.T) {
	sys, _ := setupSys(t)
	defer sys.Close()
	ctx := context.Background()

	email := "auth@example.com"
	password := "securepass"
	pwhash, _ := hash.Hash(password)

	appID, _ := binid.NewRandom()
	sys.ent.Application.Create().
		SetID(appID).
		SetName("App").
		SetDomain("app.com").
		SetRedirect("http://app.com").
		Save(ctx)

	// Create User manually
	userID, _ := binid.NewRandom()
	sys.ent.User.Create().
		SetID(userID).
		SetName("Auth User").
		SetEmail(email).
		SetPwhash(pwhash).
		Save(ctx)

	// Test Authenticate
	res := sys.UserAuthenticate(ctx, UserAuthenticateParams{
		ApplicationId: appID,
		Email:         email,
		Password:      password,
		Redirect:      "http://app.com", // matches app
		Ip:            "10.0.0.1",
		UserAgent:     "Test",
		Challenge:     "chal",
	})

	if res.ValidationErr != nil {
		t.Errorf("auth val error: %v", res.ValidationErr)
	}
	if res.SystemErr != nil {
		t.Errorf("auth sys error: %v", res.SystemErr)
	}
	if res.Cookie == nil {
		t.Error("expected cookie")
	}

	// Check Redis Challenge
	// Key: __CHALLENGE_REDIS_KEY:userID:authID
	// We need authID. From result? Result doesn't return AuthID directly publicly?
	// Oh, UserAuthenticateResult = UserLoginResult = {Cookie, E}.
	// So we can't easily get authID to check redis key directly without parsing cookie or querying DB.

	// Query DB for authentication
	auths := sys.ent.Authentication.Query().AllX(ctx)
	if len(auths) != 1 {
		t.Fatal("expected 1 auth record")
	}
	authRecord := auths[0]

	// Check Redis
	challKey := fmt.Sprintf("%s:%x:%x", __CHALLENGE_REDIS_KEY, userID, authRecord.ID)
	// Wait, code uses: fmt.Sprintf("%s:%x:%x", __CHALLENGE_REDIS_KEY, user.ID, authId)
	// user.ID and authId are string in Ent if defined as string, but keys might be cleaner?
	// In code:
	// challKey := fmt.Sprintf("%s:%x:%x", __CHALLENGE_REDIS_KEY, user.ID, authId)
	// If user.ID is string "abc", %x of string is hex of ascii bytes.
	// So we should replicate that.

	val, err := sys.redis.Get(ctx, challKey).Result()
	if err != nil {
		// Try to debug key format if fails
		t.Errorf("failed to get challenge from redis: %v (key: %s)", err, challKey)
	}
	if val != "chal" {
		t.Errorf("expected challenge 'chal', got '%s'", val)
	}
}
