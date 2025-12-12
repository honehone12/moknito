package main

import (
	"moknito/sys"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
)

type Moknito struct {
	system    sys.Sys
	validator *validator.Validate
}

func NewMocknito(logger echo.Logger) (*Moknito, error) {
	system, err := sys.NewSystem(logger)
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
