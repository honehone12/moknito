package main

import (
	"context"
	"encoding/base64"
	"flag"
	"log"
	"moknito/ent"
	"moknito/id"
	"os"

	"github.com/go-playground/validator/v10"
	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
)

type Args struct {
	Name string `validate:"min=1,max=256"`
	// using hostname_port for local, use fqdn instead
	Domain   string `validate:"hostname_port,max=256"`
	Redirect string `validate:"url,max=512"`
}

func main() {
	appName := flag.String("name", "", "application name")
	domain := flag.String("domain", "", "application domain")
	redirect := flag.String("redirect", "", "application redirect")
	flag.Parse()

	v := validator.New()
	args := Args{
		Name:     *appName,
		Domain:   *domain,
		Redirect: *redirect,
	}
	if err := v.Struct(&args); err != nil {
		log.Fatalln(err)
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
		SetName(args.Name).
		SetDomain(args.Domain).
		SetRedirect(args.Redirect).
		Save(ctx)
	if err != nil {
		log.Fatalln(err)
	}

	encId := base64.RawURLEncoding.EncodeToString([]byte(id))

	log.Printf(
		"created application id: %s name: %s domain: %s redirect: %s\n",
		encId,
		app.Name,
		app.Domain,
		app.Redirect,
	)
}
