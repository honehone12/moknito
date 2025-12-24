package sys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"moknito/binid"
	"moknito/ent"
	"moknito/ent/application"
	"moknito/ent/user"
	"moknito/hash"
	"net/http"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

type UserSys interface {
	UserRegister(
		ctx context.Context,
		p UserRegisterParams,
	) *UserRegsterResult
	UserJoin(
		ctx context.Context,
		p UserJoinParams,
	) *UserJoinResult
	UserAuthenticate(
		ctx context.Context,
		p UserAuthenticateParams,
	) *UserAuthenticateResult
}

type UserRegisterParams struct {
	Name     string
	Email    string
	Password string
}

type UserLoginParams struct {
	ApplicationId binid.BinId
	Email         string
	Password      string
	Challenge     string
	Redirect      string
	Ip            string
	UserAgent     string
}

type UserJoinParams = UserLoginParams

type UserAuthenticateParams = UserLoginParams

type UserRegsterResult = E

type UserLoginResult struct {
	Cookie *http.Cookie
	E
}

type UserJoinResult = UserLoginResult

type UserAuthenticateResult = UserLoginResult

type userRegistration struct {
	Name   string `json:"name"`
	Email  string `json:"email"`
	PwHash string `json:"pwhash"`
}

func (s *EntRdsSys) UserRegister(
	ctx context.Context,
	p UserRegisterParams,
) *UserRegsterResult {
	r := &UserRegsterResult{}

	exist, err := s.ent.User.Query().
		Where(
			user.Email(p.Email),
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

	pwHash, err := hash.Hash(p.Password)
	if err != nil {
		r.SystemErr = err
		return r
	}

	key := fmt.Sprintf("%s:%s", __USER_REGISTRATION_REDIS_KEY, p.Email)
	err = s.redis.JSONSetMode(
		ctx,
		key,
		"$", userRegistration{
			Name:   p.Name,
			Email:  p.Email,
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
	if err := s.redis.Expire(ctx, key, s.ttl.RegistrationTtl).Err(); err != nil {
		r.SystemErr = err
		return r
	}

	return r
}

func (s *EntRdsSys) checkErrorCount(
	ctx context.Context,
	email string,
) (bool, error) {
	eKey := fmt.Sprintf("%s:%s", __AUTHENTICATION_ERROR_REDIS_KEY, email)
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
	return eCount <= AUTHENTICATION_MAX_ERROR, nil
}

func (s *EntRdsSys) incrErrCount(
	ctx context.Context,
	email string,
) error {
	eKey := fmt.Sprintf("%s:%s", __AUTHENTICATION_ERROR_REDIS_KEY, email)
	if err := s.redis.Incr(ctx, eKey).Err(); err != nil {
		return err
	}
	if err := s.redis.Expire(ctx, eKey, time.Hour*5).Err(); err != nil {
		return err
	}

	return nil
}

func (s *EntRdsSys) checkRedirect(
	ctx context.Context,
	appId binid.BinId,
	redirect string,
) (bool, error) {
	app, err := s.ent.Application.Query().
		Select(application.FieldRedirect).
		Where(application.ID(appId)).
		Only(ctx)
	if ent.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}

	return app.Redirect == redirect, nil
}

func (s *EntRdsSys) UserJoin(
	ctx context.Context,
	p UserJoinParams,
) *UserJoinResult {
	r := &UserJoinResult{}

	ok, err := s.checkRedirect(ctx, p.ApplicationId, p.Redirect)
	if err != nil {
		r.SystemErr = err
		return r
	}
	if !ok {
		r.ValidationErr = errors.New("invalid redirect")
		return r
	}

	ok, err = s.checkErrorCount(ctx, p.Email)
	if err != nil {
		r.SystemErr = err
		return r
	}
	if !ok {
		r.ValidationErr = errors.New("user is locked")
		return r
	}

	userRegKey := fmt.Sprintf("%s:%s", __USER_REGISTRATION_REDIS_KEY, p.Email)
	j, err := s.redis.JSONGet(ctx, userRegKey, "$").Result()
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

	ok, err = hash.Check(p.Password, register.PwHash)
	if err != nil {
		r.SystemErr = err
		return r
	}
	if !ok {
		err := s.incrErrCount(ctx, p.Email)
		r.SystemErr = err
		r.ValidationErr = errors.New("invalid password")
		return r
	}

	userId, err := binid.NewSequential()
	if err != nil {
		r.SystemErr = err
		return r
	}
	authId, err := binid.NewSequential()
	if err != nil {
		r.SystemErr = err
		return r
	}

	tx, err := s.ent.Tx(ctx)
	err = tx.User.Create().
		SetID(userId).
		SetName(register.Name).
		SetEmail(register.Email).
		SetPwhash(register.PwHash).
		Exec(ctx)
	if err != nil {
		err := s.rollback(tx, err)
		r.SystemErr = err
		return r
	}
	err = tx.Authentication.Create().
		SetID(authId).
		SetIP(p.Ip).
		SetUserAgent(p.UserAgent).
		SetExpireAt(time.Now().Add(s.ttl.TokenTtl)).
		SetUserID(userId).
		Exec(ctx)
	if err != nil {
		err := s.rollback(tx, err)
		r.SystemErr = err
		return r
	}
	if err := tx.Commit(); err != nil {
		r.SystemErr = err
		return r
	}

	challKey := fmt.Sprintf("%s:%x:%x", __CHALLENGE_REDIS_KEY, userId, authId)
	if err := s.redis.SetEx(
		ctx,
		challKey,
		p.Challenge,
		s.ttl.CodeTtl,
	).Err(); err != nil {
		r.SystemErr = err
		return r
	}

	if err := s.redis.JSONDel(ctx, userRegKey, "$").Err(); err != nil {
		r.SystemErr = err
		return r
	}

	cookie, err := s.createAuthentication(authId, userId)
	if err != nil {
		r.SystemErr = err
		return r
	}

	r.Cookie = cookie
	return r
}

func (s *EntRdsSys) UserAuthenticate(
	ctx context.Context,
	p UserAuthenticateParams,
) *UserAuthenticateResult {
	r := &UserAuthenticateResult{}

	ok, err := s.checkRedirect(ctx, p.ApplicationId, p.Redirect)
	if err != nil {
		r.SystemErr = err
		return r
	}
	if !ok {
		r.ValidationErr = errors.New("invalid redirect")
		return r
	}

	ok, err = s.checkErrorCount(ctx, p.Email)
	if err != nil {
		r.SystemErr = err
		return r
	}
	if !ok {
		r.ValidationErr = errors.New("user is locked")
		return r
	}

	user, err := s.ent.User.Query().
		Select(
			user.FieldID,
			user.FieldPwhash,
		).
		Where(
			user.Email(p.Email),
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

	ok, err = hash.Check(p.Password, user.Pwhash)
	if err != nil {
		r.SystemErr = err
		return r
	}
	if !ok {
		err := s.incrErrCount(ctx, p.Email)
		r.SystemErr = err
		r.ValidationErr = errors.New("invalid password")
		return r
	}

	authId, err := binid.NewSequential()
	if err != nil {
		r.SystemErr = err
		return r
	}

	err = s.ent.Authentication.Create().
		SetID(authId).
		SetIP(p.Ip).
		SetUserAgent(p.UserAgent).
		SetExpireAt(time.Now().Add(s.ttl.TokenTtl)).
		SetUser(user).
		Exec(ctx)
	if err != nil {
		r.SystemErr = err
		return r
	}

	challKey := fmt.Sprintf("%s:%x:%x", __CHALLENGE_REDIS_KEY, user.ID, authId)
	if err := s.redis.SetEx(
		ctx,
		challKey,
		p.Challenge,
		s.ttl.CodeTtl,
	).Err(); err != nil {
		r.SystemErr = err
		return r
	}

	cookie, err := s.createAuthentication(authId, user.ID)
	if err != nil {
		r.SystemErr = err
		return r
	}

	r.Cookie = cookie
	return r
}
