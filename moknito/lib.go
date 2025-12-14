package moknito

import (
	"moknito/ent"
	"moknito/sys"
	"time"

	"github.com/go-playground/validator/v10"
)

type Moknito struct {
	system    sys.Sys
	validator *validator.Validate

	tokenTtl time.Duration
}

func NewMocknito() (*Moknito, error) {
	system, err := sys.NewEntRdsSys(ent.Debug())
	if err != nil {
		return nil, err
	}

	validator := validator.New()
	tokenTtl := time.Hour * 24

	return &Moknito{
		system,
		validator,
		tokenTtl,
	}, nil
}

func (m *Moknito) Close() error {
	return m.system.Close()
}
