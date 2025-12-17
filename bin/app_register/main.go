package main

import (
	"context"
	"encoding/base64"
	"flag"
	"log"
	"moknito/ent"
	"moknito/id"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
)

func main() {
	appName := flag.String("name", "", "application name")
	domain := flag.String("domain", "", "application domain")
	flag.Parse()
	if len(*appName) == 0 {
		log.Fatalln("name is required")
	}
	if len(*domain) == 0 {
		log.Fatalln("domain is required")
	}

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

	id, err := id.NewSequential()
	if err != nil {
		log.Fatalln(err)
	}

	ctx := context.Background()
	app, err := client.Application.Create().
		SetID(string(id)).
		SetName(*appName).
		SetDomain(*domain).
		Save(ctx)
	if err != nil {
		log.Fatalln(err)
	}

	encId := base64.RawURLEncoding.EncodeToString([]byte(id))

	log.Printf(
		"created application id: %s name: %s domain: %s\n",
		encId,
		app.Name,
		app.Domain,
	)
}
