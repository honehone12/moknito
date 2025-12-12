package sys

import (
	"errors"
	"io"
	"moknito/ent"
	libent "moknito/ent"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/labstack/echo/v4"
)

type Sys interface {
	UserSys
	io.Closer
}

type System struct {
	ent    *ent.Client
	logger echo.Logger
}

func NewSystem(logger echo.Logger) (*System, error) {
	// don't inject other than env
	// to prevent exposing sensitive info
	// just write within module for testing

	mysqlUri := os.Getenv("MYSQL_URI")
	if len(mysqlUri) == 0 {
		return nil, errors.New("could not found env for mysql uri")
	}

	var ent *libent.Client
	var err error
	if logger != nil {
		ent, err = libent.Open(
			"mysql",
			mysqlUri,
			libent.Log(logger.Info),
		)
	} else {
		ent, err = libent.Open(
			"mysql",
			mysqlUri,
			libent.Debug(),
		)
	}

	if err != nil {
		return nil, err
	}

	return &System{ent, logger}, nil
}

func (s *System) Close() error {
	return s.ent.Close()
}

func (s *System) Ent() *ent.Client {
	return s.ent
}
