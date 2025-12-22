package moknito

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

func TestSession_SetSession_Flow(t *testing.T) {
	client := newTestClient()

	// 1. First request should set a session cookie
	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	cookies := resp.Cookies()
	sessionCookie := findCookie(cookies, "ss")
	if sessionCookie == nil {
		t.Fatal("session cookie not set")
	}

	// 2. Second request should update the session cookie (increment nonce)
	resp2, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp2.StatusCode)
	}

	sessionCookie2 := findCookie(resp2.Cookies(), "ss")
	if sessionCookie2 == nil {
		t.Fatal("session cookie not updated on second request")
	}

	if sessionCookie.Value == sessionCookie2.Value {
		t.Error("session cookie should have different value after increment")
	}

	// 3. Request with an invalid cookie should result in a new cookie being set
	client = newTestClient() // Create a new client with a new jar
	serverURL, _ := url.Parse(testServer.URL)
	client.Jar.SetCookies(serverURL, []*http.Cookie{
		{Name: "ss", Value: "invalid-cookie-value", Path: "/"},
	})

	resp3, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("third request failed: %v", err)
	}
	defer resp3.Body.Close()

	sessionCookie3 := findCookie(resp3.Cookies(), "ss")
	if sessionCookie3 == nil {
		t.Fatal("new session cookie not set after providing invalid one")
	}
	if sessionCookie3.Value == "invalid-cookie-value" {
		t.Error("invalid session cookie was not replaced")
	}
}

func TestSession_VerifySession_AttackScenarios(t *testing.T) {
	// --- No Cookie ---
	t.Run("No Cookie", func(t *testing.T) {
		client := newTestClient()
		resp, err := postForm(client, "/api/user/00000000-0000-7000-8000-000000000000/register", nil, testServer.URL)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected status 403, got %d", resp.StatusCode)
		}
	})

	// --- Malformed Cookie ---
	t.Run("Malformed Cookie", func(t *testing.T) {
		client := newTestClient()
		serverURL, _ := url.Parse(testServer.URL)
		client.Jar.SetCookies(serverURL, []*http.Cookie{{Name: "ss", Value: "not-base64-$$", Path: "/"}})

		resp, err := postForm(client, "/api/user/00000000-0000-7000-8000-000000000000/register", nil, testServer.URL)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", resp.StatusCode)
		}
	})

	// --- Invalid Signature ---
	t.Run("Invalid Signature", func(t *testing.T) {
		client := newTestClient()
		resp, err := getRequest(client, "/session-test/") // Get a valid cookie first
		if err != nil {
			t.Fatalf("failed to get session: %v", err)
		}
		validCookie := findCookie(resp.Cookies(), "ss")
		resp.Body.Close()

		// Tamper with the signature
		tamperedValue := "a" + validCookie.Value[1:]

		client = newTestClient() // Use new client to be safe
		serverURL, _ := url.Parse(testServer.URL)
		client.Jar.SetCookies(serverURL, []*http.Cookie{{Name: "ss", Value: tamperedValue, Path: "/"}})
		resp, err = postForm(client, "/api/user/00000000-0000-7000-8000-000000000000/register", nil, testServer.URL)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", resp.StatusCode)
		}
	})

	// --- Key Not Found in Redis ---
	t.Run("Key Not Found", func(t *testing.T) {
		client := newTestClient()
		resp, err := getRequest(client, "/session-test/") // Get a valid cookie
		if err != nil {
			t.Fatalf("failed to get session: %v", err)
		}
		validCookie := findCookie(resp.Cookies(), "ss")
		resp.Body.Close()

		// Manually delete the key from Redis
		decoded, _ := base64.RawURLEncoding.DecodeString(validCookie.Value)
		// The session key is the last 16 bytes.
		sessionKey := decoded[len(decoded)-16:]
		redisKey := fmt.Sprintf("SESS:%x", sessionKey)
		testSystem.Redis().Del(context.Background(), redisKey)

		// Make request with the now-invalidated cookie
		client = newTestClient() // Use new client with the specific cookie
		serverURL, _ := url.Parse(testServer.URL)
		client.Jar.SetCookies(serverURL, []*http.Cookie{validCookie})

		resp, err = postForm(client, "/api/user/00000000-0000-7000-8000-000000000000/register", nil, testServer.URL)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", resp.StatusCode)
		}
	})
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}
