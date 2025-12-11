package sys

import (
	"errors"
	"moknito/ent"
	"os"

	_ "github.com/go-sql-driver/mysql"
)

type Sys interface {
	UserSys

	Close() error
}

type System struct {
	ent *ent.Client
}

func new(client *ent.Client) *System {
	return &System{ent: client}
}

func NewSystem() (*System, error) {
	mysqlUri := os.Getenv("MYSQL_URI")
	if len(mysqlUri) == 0 {
		return nil, errors.New("could not found env for mysql uri")
	}

	client, err := ent.Open("mysql", mysqlUri)
	if err != nil {
		return nil, err
	}

	return new(client), nil
}

func (s *System) Close() error {
	return s.ent.Close()
}

func (s *System) Ent() *ent.Client {
	return s.ent
}
