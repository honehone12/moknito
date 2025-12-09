package main

import (
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

	if err := echo.Start("localhost:8085"); err != nil {
		echo.Logger.Fatal(err)
	}
}
