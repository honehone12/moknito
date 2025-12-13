package sys

import (
	"context"
	"encoding/json"
	"fmt"
	"moknito/ent"
	"moknito/ent/user"
	"moknito/hash"
	"moknito/id"
)

type UserSys interface {
	RegisterUser(
		ctx context.Context,
		name, email, password string,
	) (bool, error)
	ConfirmUser(
		ctx context.Context,
		email, password string,
	) (*ent.User, bool, error)
}

type userRegistration struct {
	Name   string
	Email  string
	PwHash string
}

const USER_REGISTRATION_KEY = "USERREG"

func (s *EntRdsSys) RegisterUser(
	ctx context.Context,
	name, email, password string,
) (bool, error) {
	pwHash, err := hash.Hash(password)
	if err != nil {
		return false, err
	}

	exist, err := s.ent.User.Query().
		Where(user.Email(email)).
		Exist(ctx)
	if err != nil {
		return false, err
	}
	if exist {
		return false, nil
	}

	register := userRegistration{
		Name:   name,
		Email:  email,
		PwHash: pwHash,
	}
	key := fmt.Sprintf("%s:%s", USER_REGISTRATION_KEY, email)
	if err := s.redis.JSONSet(ctx, key, "$", register).Err(); err != nil {
		return false, err
	}

	return true, nil
}

func (s *EntRdsSys) ConfirmUser(
	ctx context.Context,
	email, password string,
) (*ent.User, bool, error) {
	key := fmt.Sprintf("%s:%s", USER_REGISTRATION_KEY, email)
	r, err := s.redis.JSONGet(ctx, key, "$").Result()
	if err != nil {
		return nil, false, err
	}

	register := userRegistration{}
	if err := json.Unmarshal([]byte(r), &register); err != nil {
		return nil, false, err
	}

	ok, err := hash.Check(password, register.PwHash)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, nil
	}

	id, err := id.NewSequential()
	if err != nil {
		return nil, false, err
	}

	user, err := s.ent.User.Create().
		SetID(id).
		SetName(register.Name).
		SetEmail(register.Email).
		SetPwhash(register.PwHash).
		Save(ctx)
	if err != nil {
		return nil, false, err
	}

	return user, true, nil
}
