package moknito

import (
	"moknito/ent"
	"moknito/sys"

	"github.com/go-playground/validator/v10"
)

type Moknito struct {
	system    sys.Sys
	validator *validator.Validate
}

func NewMocknito() (*Moknito, error) {
	system, err := sys.NewEntRdsSys(ent.Debug())
	if err != nil {
		return nil, err
	}

	validator := validator.New()

	return &Moknito{
		system,
		validator,
	}, nil
}

func (m *Moknito) Close() error {
	return m.system.Close()
}
