package sys

import (
	"crypto/rand"
	"encoding/base64"
	"moknito/ent/enttest"
	"moknito/token"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/alicebob/miniredis/v2/server"
	_ "github.com/mattn/go-sqlite3"
	"github.com/redis/go-redis/v9"
)

func setupSys(t *testing.T) (*EntRdsSys, *miniredis.Miniredis) {
	// Set up Env
	key := make([]byte, 32)
	rand.Read(key)
	encKey := base64.StdEncoding.EncodeToString(key)
	os.Setenv("SESSION_TOKEN_KEY", encKey)
	os.Setenv("AUTH_TOKEN_KEY", encKey)
	os.Setenv("AUTH_HOST", "test.local")
	os.Setenv("PEPPER", encKey) // Using same key for convenience as it is 32 bytes base64 encoded

	sessionSigner, err := token.NewSessionTokenSigner()
	if err != nil {
		t.Fatal(err)
	}
	authSigner, err := token.NewAuthTokenSigner()
	if err != nil {
		t.Fatal(err)
	}

	// Redis
	mr := miniredis.RunT(t)

	// Register RedisJSON mock commands
	// JSON.SET key path value [NX|XX]
	mr.Server().Register("JSON.SET", func(c *server.Peer, cmd string, args []string) {
		if len(args) < 3 {
			c.WriteError("ERR wrong number of arguments for 'JSON.SET' command")
			return
		}
		key := args[0]
		// args[1] is path (e.g., "$"), we ignore it for simplicity
		val := args[2]

		// Handle NX option
		if len(args) >= 4 && (args[3] == "NX" || args[3] == "nx") {
			if mr.Exists(key) {
				c.WriteNull()
				return
			}
		}
		mr.Set(key, val)
		c.WriteOK()
	})

	// JSON.GET key [path]
	mr.Server().Register("JSON.GET", func(c *server.Peer, cmd string, args []string) {
		if len(args) < 1 {
			c.WriteError("ERR wrong number of arguments for 'JSON.GET' command")
			return
		}
		key := args[0]
		if !mr.Exists(key) {
			c.WriteNull()
			return
		}
		val, _ := mr.Get(key)
		// Wrap in array for JSONPath "$" compatibility
		c.WriteBulk("[" + val + "]")
	})

	// JSON.DEL key [path]
	mr.Server().Register("JSON.DEL", func(c *server.Peer, cmd string, args []string) {
		if len(args) < 1 {
			c.WriteError("ERR wrong number of arguments for 'JSON.DEL' command")
			return
		}
		key := args[0]
		if mr.Exists(key) {
			mr.Del(key)
			c.WriteInt(1)
		} else {
			c.WriteInt(0)
		}
	})

	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	// Ent
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")

	sys := &EntRdsSys{
		ent:   client,
		redis: rdb,
		ttl: TtlParams{
			RegistrationTtl: time.Minute,
			SessionTtl:      time.Minute,
			TokenTtl:        time.Minute,
			CodeTtl:         time.Minute,
		},
		sessionSigner: sessionSigner,
		authSigner:    authSigner,
	}

	return sys, mr
}
