package sys

import (
	"context"
	"encoding/base64"
	"errors"
	"moknito/code"
	"moknito/ent"
	"moknito/ent/application"
	"moknito/ent/authorizedapp"
	"moknito/id"
	"time"
)

type AppSys interface {
	AppAllow(
		ctx context.Context,
		userId id.Id,
		appUuid string,
	) *AppAllowResult
	AppAuthorize(
		ctx context.Context,
		userId id.Id,
		appUuid, challenge string,
	) *AppAuthorizeResult
}

type AppAllowResult = E

type AppAuthorizeResult struct {
	Code     string
	Redirect string
	E
}

func (s *EntRdsSys) AppAllow(
	ctx context.Context,
	userId id.Id,
	appUuid string,
) *AppAllowResult {
	r := &AppAllowResult{}

	appId, err := id.FromUUIDString(appUuid)
	if err != nil {
		r.ValidationErr = err
		return r
	}

	id, err := id.NewSequential()
	if err != nil {
		r.SystemErr = err
		return r
	}

	err = s.ent.AuthorizedApp.Create().
		SetID(string(id)).
		SetApplicationID(string(appId)).
		SetUserID(string(userId)).
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

func (s *EntRdsSys) AppAuthorize(
	ctx context.Context,
	userId id.Id,
	appUuid, challenge string,
) *AppAuthorizeResult {
	r := &AppAuthorizeResult{}

	appId, err := id.FromUUIDString(appUuid)
	if err != nil {
		r.ValidationErr = err
		return r
	}

	ch, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil {
		r.ValidationErr = err
		return r
	}

	app, err := s.ent.AuthorizedApp.Query().
		Where(
			authorizedapp.UserID(string(userId)),
			authorizedapp.ApplicationID(string(appId)),
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

	id, err := id.NewSequential()
	if err != nil {
		r.SystemErr = err
		return r
	}

	now := time.Now()

	err = s.ent.Authorization.Create().
		SetID(string(id)).
		SetChallenge(ch).
		SetCode(code).
		SetCodeExpireAt(now.Add(s.codeTtl)).
		SetExpireAt(now.Add(s.tokenTtl)).
		SetApplicationID(string(appId)).
		SetUserID(string(userId)).
		Exec(ctx)
	if ent.IsConstraintError(err) {
		r.ValidationErr = err
	} else if err != nil {
		r.SystemErr = err
		return r
	}

	r.Code = base64.RawURLEncoding.EncodeToString(code)
	r.Redirect = app.Edges.Application.Redirect
	return r
}
