package sys

import (
	"context"
	"moknito/ent"
	"moknito/hash"
	"moknito/id"
)

type UserSys interface {
	CreateUser(
		ctx context.Context,
		name, email, password string,
	) (*ent.User, error)
}

func (s *System) CreateUser(
	ctx context.Context,
	name, email, password string,
) (*ent.User, error) {
	pwHash, err := hash.Hash(password)
	if err != nil {
		return nil, err
	}

	id, err := id.NewSequential()
	if err != nil {
		return nil, err
	}

	return s.ent.User.Create().
		SetID(id).
		SetName(name).
		SetEmail(email).
		SetPwhash(pwHash).
		Save(ctx)
}
