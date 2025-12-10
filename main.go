package main

import (
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

	if salt := os.Getenv("PEPPER"); len(salt) != 44 {
		echo.Logger.Fatal("env for perpper is invalid")
	}

	if err := echo.Start("localhost:8080"); err != nil {
		echo.Logger.Fatal(err)
	}
}
