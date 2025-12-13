package sys

import (
	"context"
	"encoding/json"
	"fmt"
	"moknito/ent"
	"moknito/ent/user"
	"moknito/hash"
	"moknito/id"
	"time"
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
	Name   string `json:"name"`
	Email  string `json:"email"`
	PwHash string `json:"pwhash"`
	Error  int    `json:"error"`
}

const MAX_AUTHENTICATION_ERROR = 10
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
		Where(
			user.Email(email),
			user.DeletedAtIsNil(),
		).
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
		Error:  0,
	}
	key := fmt.Sprintf("%s:%s", USER_REGISTRATION_KEY, email)
	if err := s.redis.JSONSet(ctx, key, "$", register).Err(); err != nil {
		return false, err
	}

	if err := s.redis.Expire(ctx, key, time.Minute*5).Err(); err != nil {
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

	if register.Error > MAX_AUTHENTICATION_ERROR {
		// freeze until purge
		return nil, false, nil
	}

	ok, err := hash.Check(password, register.PwHash)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		if err := s.redis.JSONNumIncrBy(ctx, key, "$.error", 1).Err(); err != nil {
			return nil, false, err
		}

		return nil, false, nil
	}

	id, err := id.NewSequential()
	if err != nil {
		return nil, false, err
	}

	// this should be tx
	// as we create login after
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
