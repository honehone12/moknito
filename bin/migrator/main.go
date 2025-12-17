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
		log.Fatalln(err)
	}

	mysqlUri := os.Getenv("MYSQL_URI")
	if len(mysqlUri) == 0 {
		log.Fatalln("could not found env for mysql uri")
	}

	client, err := ent.Open("mysql", mysqlUri, ent.Debug())
	if err != nil {
		log.Fatalln(err)
	}
	defer client.Close()

	ctx := context.Background()
	log.Println("migrating...")
	if err := client.Schema.Create(ctx); err != nil {
		log.Fatalln(err)
	}

	log.Println("done")
}
