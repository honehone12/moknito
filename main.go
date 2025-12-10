package main

import (
	"moknito/hash"
	"os"

	"github.com/joho/godotenv"
	echo4 "github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	echo := echo4.New()
	echo.Use(middleware.Logger())

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
	api.POST("/user/new", mocknito.userNew)

	if err := echo.Start("localhost:8080"); err != nil {
		echo.Logger.Fatal(err)
	}
}
