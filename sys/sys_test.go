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

	// Helper to create signer manually if we don't want to rely on NewSessionTokenSigner reading env
	// But NewSessionTokenSigner IS coupled to env.
	// We can setenv here, but it's global.
	// Better approach: Since we are in sys package, we can possibly access internal fields or
	// just use the fact that NewEntRdsSys is what we are testing?
	// Actually we want to test EntRdsSys methods, so constructing it manually is fine.
	// But EntRdsSys has private fields.
	// So we should use NewEntRdsSys but with setenv.
	// Since tests run sequentially or we can use t.Setenv which restores env.

	t.Setenv("AUTH_TOKEN_KEY", testAuthKey)
	t.Setenv("SESSION_TOKEN_KEY", testSessKey)
	t.Setenv("AUTH_HOST", "test-host")
	t.Setenv("MYSQL_URI", "dummy") // Won't be used because we inject ent in real code? No, NewEntRdsSys opens ent.
	// Ah, NewEntRdsSys opens Ent and Redis.
	// So we cannot use NewEntRdsSys if we want to inject OUR ent client and redis client.
	// But EntRdsSys struct fields are unexported?
	// s.ent, s.redis
	// Wait, internal fields are accessible within the same package.
	// So we can manually construct &EntRdsSys{...}.

	// authSignerData, _ := base64.StdEncoding.DecodeString(testAuthKey)
    // We need to re-create the signers manually or via helper.
    // token.NewAuthTokenSigner reads env.
    // Let's use t.Setenv and create signers using their public constructor if their fields are private.
    // token.AuthTokenSigner fields are private? Yes (host, key).
    
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
