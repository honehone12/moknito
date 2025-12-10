package entity

import (
	"errors"
	"moknito/ent"
	"os"
)

type Entity struct {
	ent *ent.Client
}

func NewEntity() (*Entity, error) {
	mysqlUri := os.Getenv("MYSQL_URI")
	if len(mysqlUri) == 0 {
		return nil, errors.New("could not found env for mysql uri")
	}

	ent, err := ent.Open("mysql", mysqlUri)
	if err != nil {
		return nil, err
	}

	return &Entity{ent}, nil
}

func (e *Entity) Close() error {
	return e.ent.Close()
}
