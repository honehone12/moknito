package sys

import (
	"context"
	"encoding/base64"
	"errors"
	"moknito/binid"
	"moknito/challenge"
	"moknito/ent"
	"moknito/ent/application"
	"moknito/ent/authorization"

	"moknito/token"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AuthParams struct {
	ApplicationId binid.BinId
}

type AuthTokenParams struct {
	AuthParams
	Code     string
	Verifier string
	Redirect string
}

type AuthRefreshParams struct {
	AuthParams
	Token string
}

type AuthResult struct {
	Token  *token.AuthTokenBundle
	Domain string
	E
}

type AuthorizationSys interface {
	AuthToken(ctx context.Context, p AuthTokenParams) *AuthResult
	AuthRefresh(ctx context.Context, p AuthRefreshParams) *AuthResult
}

func (s *System) AuthToken(ctx context.Context, p AuthTokenParams) *AuthResult {
	r := &AuthResult{}

	c, err := base64.RawURLEncoding.DecodeString(p.Code)
	if err != nil {
		r.ValidationErr = err
		return r
	}

	now := time.Now()

	auth, err := s.ent.Authorization.Query().
		Select(
			authorization.FieldID,
			authorization.FieldChallenge,
			authorization.FieldChallengeMethod,
			authorization.FieldCode,
			authorization.FieldUserID,
			authorization.FieldExpireAt,
		).
		Where(
			authorization.Code(c),
			authorization.CodeExpireAtGT(now),
			authorization.CodeConsumedAtIsNil(),
			authorization.ApplicationID(p.ApplicationId),
			authorization.DeletedAtIsNil(),
		).
		WithApplication(func(q *ent.ApplicationQuery) {
			q.Select(
				application.FieldRedirect,
				application.FieldDomain,
			)
		}).
		// this should be only, even though
		// i did't mark "code", "challenge" as unique (including index)
		// because of application id and expiration span limitations
		// but this does not mean there are any logic-codes to prevent "not only error"
		Only(ctx)
	if ent.IsNotFound(err) {
		r.ValidationErr = err
		return r
	} else if err != nil {
		r.SystemErr = err
		return r
	}
	if auth.ChallengeMethod != challenge.CHALLENGE_METHOD_S256 {
		r.SystemErr = errors.New("unexpected challenge method")
		return r
	}

	if p.Redirect != auth.Edges.Application.Redirect {
		r.ValidationErr = errors.New("invalid redirec url")
		return r
	}

	ok, err := challenge.Verify(p.Verifier, auth.Challenge)
	if err != nil {
		r.ValidationErr = err
		return r
	}
	if !ok {
		r.ValidationErr = errors.New("invalid challenge verifier")
		return r
	}

	apps := []string{auth.Edges.Application.Domain}

	authTkn, err := s.authSigner.CreateAuthToken(token.CreateAuthTokenParams{
		Method:       jwt.SigningMethodRS256,
		TokenType:    token.TOKEN_TYPE_AUTHORIZATION,
		AuthId:       auth.ID,
		UserId:       auth.UserID,
		Ttl:          s.ttl.TokenTtl,
		Applications: apps,
	})
	if err != nil {
		r.SystemErr = err
		return r
	}

	refTkn, err := s.authSigner.CreateAuthToken(token.CreateAuthTokenParams{
		Method:       jwt.SigningMethodRS256,
		TokenType:    token.TOKEN_TYPE_REFRESH,
		AuthId:       auth.ID,
		UserId:       auth.UserID,
		Ttl:          s.ttl.RefreshTtl,
		Applications: apps,
	})
	if err != nil {
		r.SystemErr = err
		return r
	}

	bundle := &token.AuthTokenBundle{
		AccessToken:     authTkn,
		RefreshToken:    refTkn,
		BundleTokenType: token.BUNDLE_TOKEN_TYPE_BEARER,
		ExpiresIn:       auth.ExpireAt.Sub(now).Milliseconds() / 1000,
	}

	err = s.ent.Authorization.UpdateOne(auth).
		SetCodeConsumedAt(now).
		Exec(ctx)
	if err != nil {
		r.SystemErr = err
		return r
	}

	r.Token = bundle
	r.Domain = auth.Edges.Application.Domain
	return r
}

func (s *System) AuthRefresh(ctx context.Context, p AuthRefreshParams) *AuthResult {
	r := &AuthResult{}

	app, err := s.ent.Application.Query().
		Select(application.FieldDomain).
		Where(
			application.ID(p.ApplicationId),
			application.DeletedAtIsNil(),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		r.ValidationErr = err
		return r
	} else if err != nil {
		r.SystemErr = err
		return r
	}

	apps := []string{app.Domain}

	claim, err := s.authSigner.Parse(token.ParseParams{
		Raw:          p.Token,
		Method:       jwt.SigningMethodRS256,
		TokenType:    token.TOKEN_TYPE_REFRESH,
		Applications: apps,
	})
	if err != nil {
		r.ValidationErr = err
		return r
	}

	authId, err := binid.FromUUIDString(claim.ID)
	if err != nil {
		r.ValidationErr = err
		return r
	}
	userId, err := binid.FromUUIDString(claim.Subject)
	if err != nil {
		r.ValidationErr = err
		return r
	}

	now := time.Now()

	ok, err := s.ent.Authorization.Query().
		Where(
			authorization.ID(authId),
			authorization.RefreshExpireAtGT(now),
			authorization.DeletedAtIsNil(),
			authorization.ApplicationID(app.ID),
			authorization.UserID(userId),
		).
		Exist(ctx)
	if err != nil {
		r.SystemErr = err
		return r
	}
	if !ok {
		r.ValidationErr = errors.New("authorization not found")
		return r
	}

	authTkn, err := s.authSigner.CreateAuthToken(token.CreateAuthTokenParams{
		Method:       jwt.SigningMethodRS256,
		TokenType:    token.TOKEN_TYPE_AUTHORIZATION,
		AuthId:       authId,
		UserId:       userId,
		Ttl:          s.ttl.TokenTtl,
		Applications: apps,
	})
	if err != nil {
		r.SystemErr = err
		return r
	}

	refTkn, err := s.authSigner.CreateAuthToken(token.CreateAuthTokenParams{
		Method:       jwt.SigningMethodRS256,
		TokenType:    token.TOKEN_TYPE_REFRESH,
		AuthId:       authId,
		UserId:       userId,
		Ttl:          s.ttl.RefreshTtl,
		Applications: apps,
	})
	if err != nil {
		r.SystemErr = err
		return r
	}

	bundle := &token.AuthTokenBundle{
		AccessToken:     authTkn,
		RefreshToken:    refTkn,
		BundleTokenType: token.BUNDLE_TOKEN_TYPE_BEARER,
		ExpiresIn:       s.ttl.TokenTtl.Milliseconds() / 1000,
	}

	err = s.ent.Authorization.UpdateOneID(authId).
		SetExpireAt(now.Add(s.ttl.TokenTtl)).
		SetRefreshExpireAt(now.Add(s.ttl.RefreshTtl)).
		Exec(ctx)
	if err != nil {
		r.SystemErr = err
		return r
	}

	r.Token = bundle
	r.Domain = app.Domain
	return r
}
