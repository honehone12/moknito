package sys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"moknito/ent/user"
	"moknito/hash"
	"moknito/id"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

type UserSys interface {
	UserRegister(
		ctx context.Context,
		name, email, password string,
	) (bool, error)
	UserJoin(
		ctx context.Context,
		email, password,
		ip, userAgent string,
		ttl time.Duration,
	) (id.Id, bool, error)
	UserAuthenticate(
		ctx context.Context,
		email, password,
		ip, userAgent string,
		ttl time.Duration,
	) (id.Id, bool, error)
}

type userRegistration struct {
	Name   string `json:"name"`
	Email  string `json:"email"`
	PwHash string `json:"pwhash"`
}

const MAX_AUTHENTICATION_ERROR = 10
const USER_REGISTRATION_KEY = "USERREG"
const ERROR_KEY = "ERROR"

func (s *EntRdsSys) UserRegister(
	ctx context.Context,
	name, email, password string,
) (bool, error) {
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

	pwHash, err := hash.Hash(password)
	if err != nil {
		return false, err
	}

	key := fmt.Sprintf("%s:%s", USER_REGISTRATION_KEY, email)
	if err := s.redis.JSONSetMode(
		ctx,
		key,
		"$", userRegistration{
			Name:   name,
			Email:  email,
			PwHash: pwHash,
		},
		"NX",
	).Err(); err != nil {
		return false, err
	}
	if err := s.redis.Expire(ctx, key, time.Minute*5).Err(); err != nil {
		return false, err
	}

	return true, nil
}

func (s *EntRdsSys) checkErrorCount(
	ctx context.Context,
	email string,
) (bool, error) {
	eKey := fmt.Sprintf("%s:%s", ERROR_KEY, email)
	e, err := s.redis.Get(ctx, eKey).Result()
	if errors.Is(err, redis.Nil) {
		return true, nil
	} else if err != nil {
		return false, err
	}
	eCount, err := strconv.Atoi(e)
	if err != nil {
		return false, err
	}

	// freeze until purge
	return eCount <= MAX_AUTHENTICATION_ERROR, nil
}

func (s *EntRdsSys) incrErrCount(
	ctx context.Context,
	email string,
) error {
	eKey := fmt.Sprintf("%s:%s", ERROR_KEY, email)
	if err := s.redis.Incr(ctx, eKey).Err(); err != nil {
		return err
	}
	if err := s.redis.Expire(ctx, eKey, time.Hour*5).Err(); err != nil {
		return err
	}

	return nil
}

func (s *EntRdsSys) UserJoin(
	ctx context.Context,
	email, password,
	ip, userAgent string,
	ttl time.Duration,
) (id.Id, bool, error) {
	ok, err := s.checkErrorCount(ctx, email)
	if err != nil {
		return "", false, err
	}
	if !ok {
		return "", false, nil
	}

	key := fmt.Sprintf("%s:%s", USER_REGISTRATION_KEY, email)
	r, err := s.redis.JSONGet(ctx, key, "$").Result()
	if err != nil {
		return "", false, err
	}

	var reg []userRegistration
	if err := json.Unmarshal([]byte(r), &reg); err != nil {
		return "", false, err
	}
	register := reg[0]

	ok, err = hash.Check(password, register.PwHash)
	if err != nil {
		return "", false, err
	}
	if !ok {
		err := s.incrErrCount(ctx, email)
		return "", false, err
	}

	userId, err := id.NewSequential()
	if err != nil {
		return "", false, err
	}
	authId, err := id.NewSequential()
	if err != nil {
		return "", false, err
	}

	tx, err := s.ent.Tx(ctx)
	user, err := tx.User.Create().
		SetID(string(userId)).
		SetName(register.Name).
		SetEmail(register.Email).
		SetPwhash(register.PwHash).
		Save(ctx)
	if err != nil {
		err := s.rollback(tx, err)
		return "", false, err
	}
	authenticate, err := tx.Authentication.Create().
		SetID(string(authId)).
		SetIP(ip).
		SetUserAgent(userAgent).
		SetExpireAt(time.Now().Add(ttl)).
		SetUser(user).
		Save(ctx)
	if err != nil {
		err := s.rollback(tx, err)
		return "", false, err
	}

	return id.Id(authenticate.ID), true, nil
}

func (s *EntRdsSys) UserAuthenticate(
	ctx context.Context,
	email, password,
	ip, userAgent string,
	ttl time.Duration,
) (id.Id, bool, error) {
	ok, err := s.checkErrorCount(ctx, email)
	if err != nil {
		return "", false, err
	}
	if !ok {
		return "", false, nil
	}

	user, err := s.ent.User.Query().
		Where(
			user.Email(email),
			user.DeletedAtIsNil(),
		).
		Only(ctx)
	if err != nil {
		return "", false, err
	}

	ok, err = hash.Check(password, user.Pwhash)
	if err != nil {
		return "", false, err
	}
	if !ok {
		err := s.incrErrCount(ctx, email)
		return "", false, err
	}

	authId, err := id.NewSequential()
	if err != nil {
		return "", false, err
	}

	authenticate, err := s.ent.Authentication.Create().
		SetID(string(authId)).
		SetIP(ip).
		SetUserAgent(userAgent).
		SetExpireAt(time.Now().Add(ttl)).
		SetUser(user).
		Save(ctx)
	if err != nil {
		return "", false, err
	}

	return id.Id(authenticate.ID), true, nil
}
