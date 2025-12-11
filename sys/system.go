package sys

import (
	"errors"
	"io"
	"moknito/ent"
	"os"

	_ "github.com/go-sql-driver/mysql"
)

type Sys interface {
	UserSys
	io.Closer
}

type System struct {
	ent *ent.Client
}

func NewSystem() (*System, error) {
	// don't inject other than env
	// to prevent exposing sensitive info
	// just write within module for testing

	mysqlUri := os.Getenv("MYSQL_URI")
	if len(mysqlUri) == 0 {
		return nil, errors.New("could not found env for mysql uri")
	}

	ent, err := ent.Open("mysql", mysqlUri)
	if err != nil {
		return nil, err
	}

	return &System{ent}, nil
}

func (s *System) Close() error {
	return s.ent.Close()
}

func (s *System) Ent() *ent.Client {
	return s.ent
}
