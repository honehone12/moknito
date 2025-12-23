package moknito

import (
	"net/url"
	"os"

	echo4 "github.com/labstack/echo/v4"
	echo4middleware "github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
)

func Run() {
	echo := echo4.New()
	echo.Use(echo4middleware.Logger())
	echo.Logger.SetLevel(log.INFO)
	echo.Logger.SetPrefix("MOKNITO")
	echo.HTTPErrorHandler = func(err error, ctx echo4.Context) {
		ctx.Logger().Error(err)
		echo.DefaultHTTPErrorHandler(err, ctx)
	}

	// pepper is still loaded in runtime
	// so check on initialize
	if pepper := os.Getenv("PEPPER"); len(pepper) == 0 {
		echo.Logger.Fatal("env for perpper is not set")
	}

	moknito, err := NewMocknito()
	if err != nil {
		echo.Logger.Fatal(err)
	}
	defer moknito.Close()

	uiUrl, err := url.Parse("http://localhost:3000")
	if err != nil {
		echo.Logger.Fatal(err)
	}
	uiProxy := echo4middleware.Proxy(echo4middleware.NewRoundRobinBalancer(
		[]*echo4middleware.ProxyTarget{{
			Name: "ui",
			URL:  uiUrl,
		}},
	))

	// route for public POSTs
	authGroup := echo.Group("/auth")
	authGroup.POST("/:id/token", moknito.AuthToken)

	// routes for POSTs
	api := echo.Group("/api")
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

	// routes for GETs
	info := echo.Group(
		"/info",
		moknito.VerifySession(),
		moknito.VerifyAuthentication(),
	)
	info.GET("/:id", moknito.InfoApp)

	// routes fo UIs
	// they should be static after build
	{
		echo.Group(
			"/user",
			moknito.SetSession(),
			uiProxy,
		)
		echo.Group(
			"/app",
			moknito.VerifySession(),
			moknito.VerifyAuthentication(),
			uiProxy,
		)
		echo.Group("/*", uiProxy)
	}

	if err := echo.Start("localhost:8080"); err != nil {
		echo.Logger.Fatal(err)
	}
}
