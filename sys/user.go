package sys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"moknito/ent"
	"moknito/ent/user"
	"moknito/hash"
	"moknito/id"
	"net/http"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

const MAX_AUTHENTICATION_ERROR = 10
const USER_REGISTRATION_REDIS_KEY = "USERREG"
const ERROR_REDIS_KEY = "ERROR"

type UserSys interface {
	UserRegister(
		ctx context.Context,
		name, email, password string,
	) *UserRegsterResult
	UserJoin(
		ctx context.Context,
		email, password,
		ip, userAgent string,
	) *UserJoinResult
	UserAuthenticate(
		ctx context.Context,
		email, password,
		ip, userAgent string,
	) *UserAuthenticateResult
}

type UserRegsterResult = E

type UserResult struct {
	Cookie *http.Cookie
	E
}

type UserJoinResult = UserResult

type UserAuthenticateResult = UserResult

type userRegistration struct {
	Name   string `json:"name"`
	Email  string `json:"email"`
	PwHash string `json:"pwhash"`
}

func (s *EntRdsSys) UserRegister(
	ctx context.Context,
	name, email, password string,
) *UserRegsterResult {
	r := &UserRegsterResult{}

	exist, err := s.ent.User.Query().
		Where(
			user.Email(email),
			user.DeletedAtIsNil(),
		).
		Exist(ctx)
	if err != nil {
		r.SystemErr = err
		return r
	}
	if exist {
		r.ValidationErr = errors.New("duplicated user")
		return r
	}

	pwHash, err := hash.Hash(password)
	if err != nil {
		r.SystemErr = err
		return r
	}

	key := fmt.Sprintf("%s:%s", USER_REGISTRATION_REDIS_KEY, email)
	err = s.redis.JSONSetMode(
		ctx,
		key,
		"$", userRegistration{
			Name:   name,
			Email:  email,
			PwHash: pwHash,
		},
		"NX",
	).Err()
	if errors.Is(err, redis.Nil) {
		r.ValidationErr = errors.New("duplicated user")
		return r
	} else if err != nil {
		r.SystemErr = err
		return r
	}
	if err := s.redis.Expire(ctx, key, time.Minute*5).Err(); err != nil {
		r.SystemErr = err
		return r
	}

	return r
}

func (s *EntRdsSys) checkErrorCount(
	ctx context.Context,
	email string,
) (bool, error) {
	eKey := fmt.Sprintf("%s:%s", ERROR_REDIS_KEY, email)
	e, err := s.redis.Get(ctx, eKey).Result()
	if err != nil {
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
	eKey := fmt.Sprintf("%s:%s", ERROR_REDIS_KEY, email)
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
) *UserJoinResult {
	r := &UserResult{}

	ok, err := s.checkErrorCount(ctx, email)
	if errors.Is(err, redis.Nil) {
		r.ValidationErr = errors.New("user is not registered")
		return r
	} else if err != nil {
		r.SystemErr = err
		return r
	}
	if !ok {
		r.ValidationErr = errors.New("user is locked")
		return r
	}

	key := fmt.Sprintf("%s:%s", USER_REGISTRATION_REDIS_KEY, email)
	j, err := s.redis.JSONGet(ctx, key, "$").Result()
	if errors.Is(err, redis.Nil) {
		r.ValidationErr = errors.New("registration not found")
		return r
	} else if err != nil {
		r.SystemErr = err
		return r
	}

	var reg []userRegistration
	if err := json.Unmarshal([]byte(j), &reg); err != nil {
		r.SystemErr = err
		return r
	}
	if len(reg) == 0 {
		r.SystemErr = errors.New("failed to unmarshal registration array")
		return r
	}

	register := reg[0]

	ok, err = hash.Check(password, register.PwHash)
	if err != nil {
		r.SystemErr = err
		return r
	}
	if !ok {
		err := s.incrErrCount(ctx, email)
		r.SystemErr = err
		r.ValidationErr = errors.New("invalid password")
		return r
	}

	userId, err := id.NewSequential()
	if err != nil {
		r.SystemErr = err
		return r
	}
	authId, err := id.NewSequential()
	if err != nil {
		r.SystemErr = err
		return r
	}

	tx, err := s.ent.Tx(ctx)
	user, err := tx.User.Create().
		SetID(string(userId)).
		SetName(register.Name).
		SetEmail(register.Email).
		SetPwhash(register.PwHash).
		Save(ctx)
	if err != nil {
		// we just set this err as system error because
		// user should already registered and params are validated
		// and user does not have constraints

		err := s.rollback(tx, err)
		r.SystemErr = err
		return r
	}
	auth, err := tx.Authentication.Create().
		SetID(string(authId)).
		SetIP(ip).
		SetUserAgent(userAgent).
		SetExpireAt(time.Now().Add(s.tokenTtl)).
		SetUser(user).
		Save(ctx)
	if err != nil {
		err := s.rollback(tx, err)
		r.SystemErr = err
		return r
	}
	if err := tx.Commit(); err != nil {
		r.SystemErr = err
		return r
	}

	if err := s.redis.JSONDel(ctx, key, "$").Err(); err != nil {
		r.SystemErr = err
		return r
	}

	cookie, err := s.createAuthentication(
		id.Id(auth.ID),
		id.Id(user.ID),
	)
	if err != nil {
		r.SystemErr = err
		return r
	}

	r.Cookie = cookie
	return r
}

func (s *EntRdsSys) UserAuthenticate(
	ctx context.Context,
	email, password,
	ip, userAgent string,
) *UserAuthenticateResult {
	r := &UserAuthenticateResult{}

	ok, err := s.checkErrorCount(ctx, email)
	if errors.Is(err, redis.Nil) {
		r.ValidationErr = errors.New("user is not registered")
		return r
	}
	if err != nil {
		r.SystemErr = err
		return r
	}
	if !ok {
		r.ValidationErr = errors.New("user is locked")
		return r
	}

	user, err := s.ent.User.Query().
		Where(
			user.Email(email),
			user.DeletedAtIsNil(),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		r.ValidationErr = err
		return r
	}
	if err != nil {
		r.SystemErr = err
		return r
	}

	ok, err = hash.Check(password, user.Pwhash)
	if err != nil {
		r.SystemErr = err
		return r
	}
	if !ok {
		err := s.incrErrCount(ctx, email)
		r.SystemErr = err
		r.ValidationErr = errors.New("invalid password")
		return r
	}

	authId, err := id.NewSequential()
	if err != nil {
		r.SystemErr = err
		return r
	}

	auth, err := s.ent.Authentication.Create().
		SetID(string(authId)).
		SetIP(ip).
		SetUserAgent(userAgent).
		SetExpireAt(time.Now().Add(s.tokenTtl)).
		SetUser(user).
		Save(ctx)
	if err != nil {
		r.SystemErr = err
		return r
	}

	cookie, err := s.createAuthentication(
		id.Id(auth.ID),
		id.Id(user.ID),
	)
	if err != nil {
		r.SystemErr = err
		return r
	}

	r.Cookie = cookie
	return r
}
