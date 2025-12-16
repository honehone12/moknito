package main

import (
	"moknito/hash"
	lib "moknito/moknito"
	"moknito/token"
	"net/url"
	"os"

	"github.com/joho/godotenv"
	echo4 "github.com/labstack/echo/v4"
	echo4middleware "github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
)

func main() {
	echo := echo4.New()
	echo.Use(echo4middleware.Logger())
	echo.Logger.SetLevel(log.INFO)
	echo.Logger.SetPrefix("MOKNITO")

	if err := godotenv.Load(); err != nil {
		echo.Logger.Fatal(err)
	}

	if pepper := os.Getenv("PEPPER"); len(pepper) != hash.PEPPER_ENV_LEN {
		echo.Logger.Fatal("env for perpper is invalid")
	}
	if atk := os.Getenv("AUTH_TOKEN_KEY"); len(atk) != token.SIGNATURE_KEY_ENV_LEN {
		echo.Logger.Fatal("env for auth token key is invalid")
	}
	if host := os.Getenv("AUTH_HOST"); len(host) == 0 {
		echo.Logger.Fatal("env for auth host is invalid")
	}

	moknito, err := lib.NewMocknito()
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

	api := echo.Group(
		"/api",
		moknito.OriginGuard(),
		moknito.VerifySessionCookie(),
	)
	userApi := api.Group("/user")
	userApi.POST("/register", moknito.UserRegister)
	userApi.POST("/join", moknito.UserJoin)
	userApi.POST("/authenticate", moknito.UserAuthenticate)
	api.Group("/application", moknito.VerifyAuthenticatedCookie())

	echo.Group(
		"/user",
		moknito.SetSessionCookie(),
		uiProxy,
	)
	echo.Group(
		"/application",
		moknito.VerifySessionCookie(),
		moknito.VerifyAuthenticatedCookie(),
		uiProxy,
	)
	echo.Group("/*", uiProxy)

	if err := echo.Start("localhost:8080"); err != nil {
		echo.Logger.Fatal(err)
	}
}
