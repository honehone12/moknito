package main

import (
	"moknito/moknito"

	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		panic(err)
	}

	moknito.Run()
}
