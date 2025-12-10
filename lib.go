package main

import (
	"moknito/entity"

	"github.com/go-playground/validator/v10"
)

type Moknito struct {
	entity    *entity.Entity
	validator *validator.Validate
}

func NewMocknito() (*Moknito, error) {
	entity, err := entity.NewEntity()
	if err != nil {
		return nil, err
	}

	validator := validator.New()

	return &Moknito{
		entity,
		validator,
	}, nil
}

func (m *Moknito) Close() error {
	return m.entity.Close()
}
