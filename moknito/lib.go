package moknito

import (
	"moknito/ent"
	"moknito/sys"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
)

type Moknito struct {
	system    sys.Sys
	validator *validator.Validate
}

func NewMocknito() (*Moknito, error) {
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
	}, nil
}

func (m *Moknito) SessionCookieMiddleware() echo.MiddlewareFunc {
	return m.system.SessionCookieMiddleware()
}

func (m *Moknito) Close() error {
	return m.system.Close()
}
