package main

import (
	"moknito/hash"
	"moknito/middleware"
	"net/url"
	"os"

	"github.com/joho/godotenv"
	echo4 "github.com/labstack/echo/v4"
	echo4middleware "github.com/labstack/echo/v4/middleware"
)

func main() {
	echo := echo4.New()
	echo.Use(echo4middleware.Logger())

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

	originGuard, err := middleware.OriginGuard()
	if err != nil {
		echo.Logger.Fatal(err)
	}

	api := echo.Group("/api")
	api.Use(originGuard)
	api.POST("/user/new", mocknito.userNew)

	ui := echo.Group("/*")
	uiUrl, err := url.Parse("http://localhost:3000")
	if err != nil {
		echo.Logger.Fatal(err)
	}
	uiBalancer := echo4middleware.NewRoundRobinBalancer(
		[]*echo4middleware.ProxyTarget{
			{
				Name: "dev",
				URL:  uiUrl,
			},
		},
	)
	ui.Use(echo4middleware.Proxy(uiBalancer))

	if err := echo.Start("localhost:8080"); err != nil {
		echo.Logger.Fatal(err)
	}
}
