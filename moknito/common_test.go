package moknito

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
)

var testServer *httptest.Server
var testMoknito *Moknito

func TestMain(m *testing.M) {
	// Load .env
	if err := godotenv.Load("../.env"); err != nil {
		panic("failed to load .env: " + err.Error())
	}

	// Set ORIGIN to test server URL (will be updated after server starts)
	os.Setenv("ORIGIN", "http://127.0.0.1")

	// Create Moknito instance
	moknito, err := NewMocknito()
	if err != nil {
		panic("failed to create moknito: " + err.Error())
	}
	testMoknito = moknito

	// Setup Echo server
	e := echo.New()
	setupRoutes(e, moknito)

	// Create test server
	testServer = httptest.NewServer(e)
	defer testServer.Close()

	// Update ORIGIN to match test server
	os.Setenv("ORIGIN", testServer.URL)
	moknito.origin = testServer.URL

	// Run tests
	code := m.Run()

	// Cleanup
	moknito.Close()
	os.Exit(code)
}

func setupRoutes(e *echo.Echo, moknito *Moknito) {
	// Auth routes (public)
	authGroup := e.Group("/auth")
	authGroup.POST("/:id/token", moknito.AuthToken)

	// API routes
	api := e.Group("/api")
	userApi := api.Group(
		"/user",
		moknito.OriginGuard(), moknito.VerifySession(),
	)
	userApi.POST("/:id/register", moknito.UserRegister)
	userApi.POST("/:id/join", moknito.UserJoin)
	userApi.POST("/:id/authenticate", moknito.UserAuthenticate)

	appApi := api.Group("/app", moknito.VerifyAuthentication())
	appApi.POST("/:id/allow", moknito.AppAllow)
	appApi.POST("/:id/authorize", moknito.AppAuthorize)

	// Info routes
	info := e.Group(
		"/info",
		moknito.VerifySession(),
		moknito.VerifyAuthentication(),
	)
	info.GET("/:id", moknito.InfoApp)

	// Session test route
	sessionTest := e.Group("/session-test", moknito.SetSession())
	sessionTest.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})
}

// Helper to create HTTP client with cookie jar
func newTestClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}
}

// Helper to create form request
func postForm(client *http.Client, urlPath string, data url.Values, origin string) (*http.Response, error) {
	req, err := http.NewRequest("POST", testServer.URL+urlPath, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	return client.Do(req)
}

// Helper to create GET request
func getRequest(client *http.Client, urlPath string) (*http.Response, error) {
	return client.Get(testServer.URL + urlPath)
}
