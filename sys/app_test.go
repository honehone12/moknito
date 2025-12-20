package sys

import (
	"context"
	"encoding/base64"
	"fmt"
	"moknito/id"
	"testing"
	"time"
)

func TestApp_AppAllow(t *testing.T) {
	sys, _ := setupSys(t)
	defer sys.Close()
	ctx := context.Background()

	userID, _ := id.NewRandom()
	appID, _ := id.NewRandom()
	appUuid, _ := appID.ToUUID()

	// Create App
	sys.ent.Application.Create().
		SetID(string(appID)).
		SetDomain("dom").
		SetRedirect("sub").
		SetName("name").
		Save(ctx)

	// Create User
	sys.ent.User.Create().
		SetID(string(userID)).
		SetName("Test User").
		SetEmail("test@example.com").
		SetPwhash("hash").
		Save(ctx)

	// Call Allow
	res := sys.AppAllow(ctx, userID, appUuid.String())
	if res.ValidationErr != nil {
		t.Error(res.ValidationErr)
	}
	if res.SystemErr != nil {
		t.Error(res.SystemErr)
	}

	// Verify DB reference
	exists, _ := sys.ent.AuthorizedApp.Query().Exist(ctx)
	if !exists {
		t.Error("AuthorizedApp not created")
	}
}

func TestApp_AppAuthorize(t *testing.T) {
	sys, _ := setupSys(t)
	defer sys.Close()
	ctx := context.Background()

	userID, _ := id.NewRandom()
	authID, _ := id.NewRandom()
	appID, _ := id.NewRandom()
	appUuid, _ := appID.ToUUID()

	// 1. Setup Data
	sys.ent.Application.Create().
		SetID(string(appID)).
		SetDomain("dom").
		SetRedirect("http://redirect.com"). // match redirect
		SetName("name").
		Save(ctx)

	// Create User
	sys.ent.User.Create().
		SetID(string(userID)).
		SetName("u").SetEmail("e").SetPwhash("hash").
		Save(ctx)

	// Create AuthorizedApp (Must allow first)
	authAppID, _ := id.NewRandom()
	_, err := sys.ent.AuthorizedApp.Create().
		SetID(string(authAppID)).
		SetUserID(string(userID)).
		SetApplicationID(string(appID)).
		Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Set Redis Challenge
	// Key: __CHALLENGE_REDIS_KEY:UserId:AuthId
	// Note: system.go uses %x for IDs in Sprintf.
	challKey := fmt.Sprintf("%s:%x:%x", __CHALLENGE_REDIS_KEY, userID, authID)
	challengeRaw := []byte("challenge_bytes")
	challengeStr := base64.RawURLEncoding.EncodeToString(challengeRaw) // Stored in redis as string (from UserAuthenticate)
	// Actually UserAuthenticate stores p.Challenge which is string.
	// But AppAuthorize does: clg, _ := redis.Get(). chall, _ := base64.DecodeString(clg).
	// So redis must store base64 encoded string.
	
	sys.redis.Set(ctx, challKey, challengeStr, time.Minute)

	// 2. Call Authorize
	res := sys.AppAuthorize(ctx, AppAuthorizeParams{
		UserId:  userID,
		AuthId:  authID,
		AppUuid: appUuid.String(),
	})

	if res.ValidationErr != nil {
		t.Fatalf("authorize val err: %v", res.ValidationErr)
	}
	if res.SystemErr != nil {
		t.Fatalf("authorize sys err: %v", res.SystemErr)
	}

	if res.Code == "" {
		t.Error("expected code")
	}
	if res.Redirect != "http://redirect.com" {
		t.Errorf("wrong redirect: %s", res.Redirect)
	}

	// Verify Authorization created
	// Check challenge match
	auth, err := sys.ent.Authorization.Query().Only(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// auth.Challenge should be bytes of challengeRaw
	// Verify challenge is stored correctly (bytes)
	// Logic: chall, _ := base64.DecodeString(clg). SetChallenge(chall).
	// So auth.Challenge == challengeRaw
	if string(auth.Challenge) != string(challengeRaw) {
		t.Errorf("challenge mismatch in DB")
	}
}
