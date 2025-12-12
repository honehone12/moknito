package main

import (
	"moknito/hash"
	"moknito/middleware"
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

	mocknito, err := NewMocknito()
	if err != nil {
		echo.Logger.Fatal(err)
	}
	defer mocknito.Close()

	api := echo.Group("/api")
	originGuard, err := middleware.OriginGuard()
	if err != nil {
		echo.Logger.Fatal(err)
	}
	api.Use(originGuard)
	api.POST("/user/new", mocknito.userNew)

	ui := echo.Group("/*")
	uiUrl, err := url.Parse("http://localhost:3000")
	if err != nil {
		echo.Logger.Fatal(err)
	}
	// this should be static route after build
	ui.Use(echo4middleware.Proxy(echo4middleware.NewRoundRobinBalancer(
		[]*echo4middleware.ProxyTarget{
			{
				Name: "ui",
				URL:  uiUrl,
			},
		},
	)))

	if err := echo.Start("localhost:8080"); err != nil {
		echo.Logger.Fatal(err)
	}
}
