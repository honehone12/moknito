package main

import (
	"context"
	"log"
	"moknito/ent"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load("../../.env"); err != nil {
		log.Fatal(err)
	}

	mysqlUri := os.Getenv("MYSQL_URI")
	if len(mysqlUri) == 0 {
		log.Fatal("could not found env for mysql uri")
	}

	client, err := ent.Open("mysql", mysqlUri)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()
	log.Println("migrating...")
	if err := client.Schema.Create(ctx); err != nil {
		log.Fatal(err)
	}

	log.Println("done")
}
