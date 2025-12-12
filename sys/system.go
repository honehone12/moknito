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

type EntSys struct {
	ent *ent.Client
}

func NewEntSys(entOptions ...ent.Option) (*EntSys, error) {
	// don't inject other than env
	// to prevent exposing sensitive info
	// just write within module for testing

	mysqlUri := os.Getenv("MYSQL_URI")
	if len(mysqlUri) == 0 {
		return nil, errors.New("could not found env for mysql uri")
	}

	ent, err := ent.Open(
		"mysql",
		mysqlUri,
		entOptions...,
	)

	if err != nil {
		return nil, err
	}

	return &EntSys{ent}, nil
}

func (s *EntSys) Close() error {
	return s.ent.Close()
}

func (s *EntSys) Ent() *ent.Client {
	return s.ent
}
