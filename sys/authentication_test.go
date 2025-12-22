package sys

import (
	"context"
	"moknito/id"
	"moknito/token"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestAuthentication_VerifyAuthentication(t *testing.T) {
	sys, _ := setupSys(t)
	defer sys.Close()
	ctx := context.Background()

	// 1. Setup Data
	userID, _ := id.NewRandom()
	authID, _ := id.NewRandom()

	sys.ent.User.Create().
		SetID(string(userID)).
		SetName("u").SetEmail("e").SetPwhash("p").
		Save(ctx)

	_, err := sys.ent.Authentication.Create().
		SetID(string(authID)).
		SetUserID(string(userID)).
		SetExpireAt(time.Now().Add(time.Hour)).
		SetIP("127.0.0.1").
		SetUserAgent("test-agent").
		Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	authUuid, _ := authID.ToUUID()
	userUuid, _ := userID.ToUUID()

	// 2. Create Valid Token
	tokenStr, err := sys.authSigner.CreateAuthToken(token.CreateAuthTokenParams{
		Method:    jwt.SigningMethodHS256,
		TokenType: token.TOKEN_TYPE_AUTHENTICATION,
		AuthUuid:  authUuid,
		UserUuid:  userUuid,
		Ttl:       time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	cookie := &http.Cookie{
		Name:  AUTHENTICATED_COOKIE_KEY,
		Value: tokenStr,
	}

	// 3. Test Success
	res := sys.VerifyAuthentication(ctx, cookie)
	if res.ValidationErr != nil {
		t.Errorf("expected success, got validation err: %v", res.ValidationErr)
	}
	if res.SystemErr != nil {
		t.Errorf("expected success, got system err: %v", res.SystemErr)
	}
	if res.UserId != userID {
		t.Errorf("expected userid %v, got %v", userID, res.UserId)
	}
	if res.AuthId != authID {
		t.Errorf("expected authid %v, got %v", authID, res.AuthId)
	}

	// 4. Test missing/expired Auth in DB
	// Create Expired Auth
	expiredAuthID, _ := id.NewRandom()
	expiredUuid, _ := expiredAuthID.ToUUID()

	sys.ent.Authentication.Create().
		SetID(string(expiredAuthID)).
		SetUserID(string(userID)).
		SetExpireAt(time.Now().Add(-time.Hour)). // expired
		SetIP("127.0.0.1").
		SetUserAgent("test").
		Save(ctx)

	// Create token for this expired auth
	expiredTokenStr, _ := sys.authSigner.CreateAuthToken(token.CreateAuthTokenParams{
		Method:    jwt.SigningMethodHS256,
		TokenType: token.TOKEN_TYPE_AUTHENTICATION,
		AuthUuid:  expiredUuid,
		UserUuid:  userUuid,
		Ttl:       time.Hour,
	})
	expiredCookie := &http.Cookie{Name: AUTHENTICATED_COOKIE_KEY, Value: expiredTokenStr}

	res = sys.VerifyAuthentication(ctx, expiredCookie)
	if res.ValidationErr == nil {
		t.Error("expected validation error for expired auth, got nil")
	}

	// 5. Test wrong UserID in token
	wrongUser, _ := id.NewRandom()
	wrongUserUuid, _ := wrongUser.ToUUID()
	wrongTokenStr, _ := sys.authSigner.CreateAuthToken(token.CreateAuthTokenParams{
		Method:    jwt.SigningMethodHS256,
		TokenType: token.TOKEN_TYPE_AUTHENTICATION,
		AuthUuid:  authUuid,      // points to valid auth
		UserUuid:  wrongUserUuid, // but mismatch user
		Ttl:       time.Hour,
	})
	wrongCookie := &http.Cookie{Name: AUTHENTICATED_COOKIE_KEY, Value: wrongTokenStr}

	res = sys.VerifyAuthentication(ctx, wrongCookie)
	if res.ValidationErr == nil {
		t.Error("expected validation error for subject mismatch, got nil")
	} else if res.ValidationErr.Error() != "no active authentication found" {
		t.Errorf("expected 'wrong subject' error, got %v", res.ValidationErr)
	}
}

func TestAuthentication_CreateAuthentication(t *testing.T) {
	sys, _ := setupSys(t)
	defer sys.Close()

	userID, _ := id.NewRandom()
	authID, _ := id.NewRandom()

	cookie, err := sys.createAuthentication(authID, userID)
	if err != nil {
		t.Fatalf("createAuthentication failed: %v", err)
	}
	if cookie.Name != AUTHENTICATED_COOKIE_KEY {
		t.Errorf("wrong cookie name")
	}

	// Parse back
	claims, err := sys.authSigner.Parse(token.ParseParams{
		Raw:    cookie.Value,
		Method: jwt.SigningMethodHS256,
	})
	if err != nil {
		t.Errorf("failed to parse generated token: %v", err)
	}
	if claims.Subject != string(userID) {
		// Wait, claims.Subject is string(uuid).
		// userId is id.Id (raw bytes).
		// In createAuthentication: userUuid, err := userId.ToUUID(). Subject := userUuid.String()
		// So claims.Subject should be UUID string.

		u, _ := userID.ToUUID()
		if claims.Subject != u.String() {
			t.Errorf("expected subject %s, got %s", u.String(), claims.Subject)
		}
	}
}
