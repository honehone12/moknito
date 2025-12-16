package sys

import (
	"context"
	"moknito/ent"
	"moknito/ent/enttest"
	"moknito/token"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	_ "github.com/mattn/go-sqlite3"
	"github.com/redis/go-redis/v9"
)

const (
	testTokenTtl = time.Hour
	testAuthKey  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 44 chars, 32 bytes decoded
	testSessKey  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 44 chars, 32 bytes decoded
)

func setupTestSys(t *testing.T) (*EntRdsSys, *miniredis.Miniredis) {
	// 1. Mock Ent with SQLite
	// enttest.Open will create a client using sqlite and migrate schema.
	// Using "file:ent?mode=memory&cache=shared&_fk=1" for in-memory
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() { client.Close() })

	// 2. Mock Redis with miniredis
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	t.Cleanup(mr.Close)

	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	// 3. Create real token signers with test keys
	// NewEntRdsSys reads env vars. We can either mock env vars or manually construct the struct.
	// Manually constructing is cleaner to avoid side effects on parallel tests if we used env.

	t.Setenv("AUTH_TOKEN_KEY", testAuthKey)
	t.Setenv("SESSION_TOKEN_KEY", testSessKey)
	t.Setenv("AUTH_HOST", "test-host")
	t.Setenv("MYSQL_URI", "dummy")

	// So:
	authSigner, err := token.NewAuthTokenSigner()
	if err != nil {
		t.Fatalf("failed to create auth token signer: %v", err)
	}

	sessionSigner, err := token.NewSessionTokenSigner()
	if err != nil {
		t.Fatalf("failed to create session token signer: %v", err)
	}

	sys := &EntRdsSys{
		ent:           client,
		redis:         rdb,
		tokenTtl:      testTokenTtl,
		authSigner:    authSigner,
		sessionSigner: sessionSigner,
	}

	return sys, mr
}

func createTestContext(t *testing.T, sys *EntRdsSys) (context.Context, *ent.Tx) {
	// Helper to create a context/tx if needed, or just return basic context
	return context.Background(), nil
}
