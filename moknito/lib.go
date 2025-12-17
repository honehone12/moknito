package moknito

import (
	"errors"
	"moknito/ent"
	"moknito/sys"
	"os"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
)

type Moknito struct {
	system    sys.Sys
	validator *validator.Validate

	origin string
}

func NewMocknito() (*Moknito, error) {
	// don't inject other than env
	// to prevent exposing sensitive info
	// just write within module for testing

	origin := os.Getenv("ORIGIN")
	if len(origin) == 0 {
		return nil, errors.New("could not find origin env")
	}

	system, err := sys.NewEntRdsSys(
		time.Hour*24,
		ent.Debug(),
	)
	if err != nil {
		return nil, err
	}

	validator := validator.New()

	return &Moknito{
		system,
		validator,
		origin,
	}, nil
}

func (m *Moknito) Close() error {
	return m.system.Close()
}

func (m *Moknito) bind(ctx echo.Context, target any) error {
	if err := ctx.Bind(target); err != nil {
		return err
	}

	if err := m.validator.Struct(target); err != nil {
		return err
	}

	return nil
}
