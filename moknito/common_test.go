package moknito

import (
	"context"
	"fmt"
	"io"
	"moknito/ent"
	"moknito/ent/user"
	"moknito/id"
	"moknito/sys"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
)

var testServer *httptest.Server
var testMoknito *Moknito
var testSystem *sys.EntRdsSys

type testClientIDs struct {
	UserID      id.Id
	AppID       id.Id
	AppUUID     string
	AppRedirect string
	UserEmail   string
	UserPass    string
}

func TestMain(m *testing.M) {
	// Load .env
	if err := godotenv.Load("../.env"); err != nil {
		panic("failed to load .env: " + err.Error())
	}

	os.Setenv("ORIGIN", "http://127.0.0.1")

	// Instantiate sys.EntRdsSys directly
	system, err := sys.NewEntRdsSys(
		sys.TtlParams{
			RegistrationTtl: time.Minute * 5,
			SessionTtl:      time.Hour,
			TokenTtl:        time.Hour * 12,
			CodeTtl:         time.Minute * 5,
		},
		ent.Debug(),
	)
	if err != nil {
		panic("failed to create sys.EntRdsSys: " + err.Error())
	}
	testSystem = system

	// Manually construct Moknito
	origin := os.Getenv("ORIGIN")
	regex, err := NewRegexValidator()
	if err != nil {
		panic("failed to create regex validator: " + err.Error())
	}
	validate := validator.New()
	validate.RegisterValidation("uuid7", regex.ValidateUuidV7)

	moknito := &Moknito{
		system:    testSystem,
		validator: validate,
		origin:    origin,
		regex:     regex,
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

// newAuthenticatedTestClient creates a user via API and returns a client with a valid auth cookie.
func newAuthenticatedTestClient(t *testing.T) (*http.Client, testClientIDs) {
	ctx := context.Background()
	client := newTestClient()

	// 1. Get session cookie
	resp, err := getRequest(client, "/session-test/")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	resp.Body.Close()

	// 2. Create App in DB for user registration context
	appID, _ := id.NewSequential()
	appUUID, _ := appID.ToUUID()
	appRedirect := fmt.Sprintf("https://test.app/%s/cb", uuid.NewString())
	_, err = testSystem.Ent().Application.Create().
		SetID(string(appID)).
		SetName("Test App "+uuid.NewString()).
		SetDomain("test.app."+uuid.NewString()).
		SetRedirect(appRedirect).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create app: %v", err)
	}

	// 3. Register user
	userEmail := fmt.Sprintf("%s@example.com", uuid.NewString())
	userPass := "a-very-secure-password-123"
	regData := url.Values{
		"name":     {"Test User"},
		"email":    {userEmail},
		"password": {userPass},
	}
	resp, err = postForm(client, "/api/user/"+appUUID.String()+"/register", regData, testServer.URL)
	if err != nil {
		t.Fatalf("register request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("register request failed with status %d, body: %s", resp.StatusCode, string(body))
	}

	// 4. Join (which logs in the user and sets the auth cookie)
	joinData := url.Values{
		"email":            {userEmail},
		"password":         {userPass},
		"challenge":        {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		"challenge_method": {"S256"},
		"redirect":         {appRedirect},
	}
	resp, err = postForm(client, "/api/user/"+appUUID.String()+"/join", joinData, testServer.URL)
	if err != nil {
		t.Fatalf("join request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("join request failed with status %d, body: %s", resp.StatusCode, string(body))
	}

	// 5. Retrieve created user to get ID
	user, err := testSystem.Ent().User.Query().Where(user.Email(userEmail)).Only(ctx)
	if err != nil {
		t.Fatalf("failed to query created user: %v", err)
	}

	ids := testClientIDs{
		UserID:      id.Id(user.ID),
		AppID:       appID,
		AppUUID:     appUUID.String(),
		AppRedirect: appRedirect,
		UserEmail:   userEmail,
		UserPass:    userPass,
	}

	return client, ids
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