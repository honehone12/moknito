package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"moknito/sys"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"moknito/ent/migrate"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
)

func TestMain(m *testing.M) {
	// here is dotenv ///////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////
	if err := godotenv.Load(); err != nil {
		err := errors.Join(err, errors.New("Could not load .env file, relying on environment variables"))
		panic(err)
	}

	// Run all tests.
	exitCode := m.Run()
	os.Exit(exitCode)
}

func TestUserNew_E2E(t *testing.T) {
	m, err := NewMocknito(nil)
	if err != nil {
		t.Fatalf("Failed to create moknito instance: %v", err)
	}
	defer m.Close()

	// Auto-migration for test database
	// In a real project, you might want a more sophisticated migration strategy
	if err := m.system.(*sys.System).Ent().Schema.Create(
		context.Background(),
		migrate.WithDropColumn(true),
		migrate.WithDropIndex(true),
	); err != nil {
		t.Logf("failed to create schema, might already exist: %v", err)
	}

	e := echo.New()
	api := e.Group("/api")
	api.POST("/user/new", m.userNew)
	server := httptest.NewServer(e)
	defer server.Close()

	// To give a unique email for each test run
	uniqueEmail := func(base string) string {
		return fmt.Sprintf("%d-%s", time.Now().UnixNano(), base)
	}

	t.Run("Success", func(t *testing.T) {
		testUserName := "testuser-success"
		testUserEmail := uniqueEmail("success@example.com")
		testUserPassword := "password123"

		// clean up codes //////////////////////////////////////////////////
		////////////////////////////////////////////////////////////////////
		// defer func() {
		// 	_, err := m.system.(*sys.System).Ent().User.
		// 		Delete().
		// 		Where(user.EmailEQ(testUserEmail)).
		// 		Exec(context.Background())
		// 	if err != nil {
		// 		t.Logf("cleanup failed for user %s: %v", testUserEmail, err)
		// 	}
		// }()

		form := url.Values{}
		form.Add("name", testUserName)
		form.Add("email", testUserEmail)
		form.Add("password", testUserPassword)

		resp, err := http.PostForm(server.URL+"/api/user/new", form)
		if err != nil {
			t.Fatalf("Failed to send request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Expected status code %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, body)
		}

		var resBody userNewResponse
		if err := json.NewDecoder(resp.Body).Decode(&resBody); err != nil {
			t.Fatalf("Failed to decode response body: %v", err)
		}

		if resBody.Name != testUserName {
			t.Errorf("Expected user name '%s', got '%s'", testUserName, resBody.Name)
		}
		if resBody.Email != testUserEmail {
			t.Errorf("Expected user email '%s', got '%s'", testUserEmail, resBody.Email)
		}
	})

	t.Run("BadRequest - Invalid Input", func(t *testing.T) {
		form := url.Values{}
		form.Add("name", "") // Invalid: empty name
		form.Add("email", "not-an-email")
		form.Add("password", "short") // Invalid: less than 8 chars

		resp, err := http.PostForm(server.URL+"/api/user/new", form)
		if err != nil {
			t.Fatalf("Failed to send request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("Expected status code %d, got %d", http.StatusBadRequest, resp.StatusCode)
		}
	})

	t.Run("Duplicate Email", func(t *testing.T) {
		testUserName := "testuser-duplicate"
		testUserEmail := uniqueEmail("duplicate@example.com")
		testUserPassword := "password123"

		// clean up codes //////////////////////////////////////////////////
		////////////////////////////////////////////////////////////////////
		// defer func() {
		// 	_, err := m.system.(*sys.System).Ent().User.
		// 		Delete().
		// 		Where(user.EmailEQ(testUserEmail)).
		// 		Exec(context.Background())
		// 	if err != nil {
		// 		t.Logf("cleanup failed for user %s: %v", testUserEmail, err)
		// 	}
		// }()

		// First request - should succeed
		form1 := url.Values{}
		form1.Add("name", testUserName)
		form1.Add("email", testUserEmail)
		form1.Add("password", testUserPassword)

		resp1, err := http.PostForm(server.URL+"/api/user/new", form1)
		if err != nil {
			t.Fatalf("Failed to send first request: %v", err)
		}
		defer resp1.Body.Close()

		if resp1.StatusCode != http.StatusOK {
			t.Fatalf("Expected status OK for first request, got %d", resp1.StatusCode)
		}

		// Second request with same email - should fail
		form2 := url.Values{}
		form2.Add("name", "another-user")
		form2.Add("email", testUserEmail) // Same email
		form2.Add("password", "anotherpassword")

		resp2, err := http.PostForm(server.URL+"/api/user/new", form2)
		if err != nil {
			t.Fatalf("Failed to send second request: %v", err)
		}
		defer resp2.Body.Close()

		if resp2.StatusCode != http.StatusInternalServerError {
			body, _ := io.ReadAll(resp2.Body)
			t.Fatalf("Expected status code %d on duplicate email, got %d. Body: %s", http.StatusInternalServerError, resp2.StatusCode, body)
		}
	})
}
