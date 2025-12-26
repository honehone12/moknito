package sys

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"moknito/binid"
	"moknito/challenge"
	"moknito/code"
	"moknito/ent"
	"moknito/ent/application"
	"moknito/ent/authorizedapp"

	"time"

	"github.com/redis/go-redis/v9"
)

type AppSys interface {
	AppAllow(
		ctx context.Context,
		userId binid.BinId,
		appUuid string,
	) *AppAllowResult
	AppAuthorize(
		ctx context.Context,
		p AppAuthorizeParams,
	) *AppAuthorizeResult
}

type AppAuthorizeParams struct {
	UserId  binid.BinId
	AuthId  binid.BinId
	AppUuid string
}

type AppAllowResult = E

type AppAuthorizeResult struct {
	Code     string
	Redirect string
	E
}

func (s *System) AppAllow(
	ctx context.Context,
	userId binid.BinId,
	appUuid string,
) *AppAllowResult {
	r := &AppAllowResult{}

	appId, err := binid.FromUUIDString(appUuid)
	if err != nil {
		r.ValidationErr = err
		return r
	}

	exist, err := s.ent.AuthorizedApp.Query().
		Where(
			authorizedapp.UserID(userId),
			authorizedapp.ApplicationID(appId),
			authorizedapp.DeletedAtIsNil(),
		).
		Exist(ctx)
	if err != nil {
		r.SystemErr = err
		return r
	}
	if exist {
		return r
	}

	id, err := binid.NewSequential()
	if err != nil {
		r.SystemErr = err
		return r
	}

	err = s.ent.AuthorizedApp.Create().
		SetID(id).
		SetApplicationID(appId).
		SetUserID(userId).
		Exec(ctx)
	if ent.IsConstraintError(err) {
		r.ValidationErr = err
		return r
	} else if err != nil {
		r.SystemErr = err
		return r
	}

	return r
}

func (s *System) AppAuthorize(
	ctx context.Context,
	p AppAuthorizeParams,
) *AppAuthorizeResult {
	r := &AppAuthorizeResult{}

	appId, err := binid.FromUUIDString(p.AppUuid)
	if err != nil {
		r.ValidationErr = err
		return r
	}

	challKey := fmt.Sprintf(
		"%s:%x:%x",
		__CHALLENGE_REDIS_KEY,
		p.UserId,
		p.AuthId,
	)
	clg, err := s.redis.Get(ctx, challKey).Result()
	if errors.Is(err, redis.Nil) {
		r.ValidationErr = errors.New("could not find challenge")
		return r
	} else if err != nil {
		r.SystemErr = err
		return r
	}

	chall, err := base64.RawURLEncoding.DecodeString(clg)
	if err != nil {
		r.ValidationErr = err
		return r
	}

	app, err := s.ent.AuthorizedApp.Query().
		Select(authorizedapp.FieldID).
		Where(
			authorizedapp.UserID(p.UserId),
			authorizedapp.ApplicationID(appId),
			authorizedapp.DeletedAtIsNil(),
		).
		WithApplication(func(q *ent.ApplicationQuery) {
			q.Select(
				application.FieldID,
				application.FieldRedirect,
			)
		}).
		Only(ctx)
	if ent.IsNotFound(err) {
		r.ValidationErr = errors.New("application is not authorized")
		return r
	} else if err != nil {
		r.SystemErr = err
		return r
	}

	code, err := code.NewCode()
	if err != nil {
		r.SystemErr = err
		return r
	}

	id, err := binid.NewSequential()
	if err != nil {
		r.SystemErr = err
		return r
	}

	now := time.Now()

	err = s.ent.Authorization.Create().
		SetID(id).
		SetChallengeMethod(challenge.CHALLENGE_METHOD_S256).
		SetChallenge(chall).
		SetCode(code).
		SetCodeExpireAt(now.Add(s.ttl.CodeTtl)).
		SetExpireAt(now.Add(s.ttl.TokenTtl)).
		SetRefreshExpireAt(now.Add(s.ttl.RefreshTtl)).
		SetApplicationID(appId).
		SetUserID(p.UserId).
		Exec(ctx)
	if ent.IsConstraintError(err) {
		r.ValidationErr = err
		return r
	} else if err != nil {
		r.SystemErr = err
		return r
	}

	r.Code = base64.RawURLEncoding.EncodeToString(code)
	r.Redirect = app.Edges.Application.Redirect
	return r
}
