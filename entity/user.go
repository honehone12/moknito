package entity

import (
	"context"
	"moknito/ent"
	"moknito/hash"
	"moknito/id"
)

func (e *Entity) CreateUser(
	ctx context.Context,
	name string,
	email string,
	password string,
) (*ent.User, error) {
	pwHash, err := hash.Hash(password)
	if err != nil {
		return nil, err
	}

	id, err := id.NewSequential()
	if err != nil {
		return nil, err
	}

	return e.ent.User.Create().
		SetID(id).
		SetName(name).
		SetEmail(email).
		SetPwhash(pwHash).
		Save(ctx)
}
