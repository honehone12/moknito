package sys

import (
	"context"
	"encoding/base64"
	"errors"
	"moknito/challenge"
	"moknito/ent"
	"moknito/ent/application"
	"moknito/ent/authorization"
	"moknito/id"
	"moknito/token"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type AuthTokenParams struct {
	ApplicationId id.Id
}

type AuthTokenCodeParams struct {
	AuthTokenParams
	Code     string
	Verifier string
	Redirect string
}

type AuthTokenResult struct {
	Token  *token.AuthTokenBundle
	Domain string
	E
}

type AuthorizationSigner interface {
	AuthTokenCode(
		ctx context.Context,
		p AuthTokenCodeParams,
	) *AuthTokenResult
}

func (s *EntRdsSys) AuthTokenCode(
	ctx context.Context,
	p AuthTokenCodeParams,
) *AuthTokenResult {
	r := &AuthTokenResult{}

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
			authorization.ApplicationID(string(p.ApplicationId)),
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

	authUuid, err := uuid.FromBytes([]byte(auth.ID))
	if err != nil {
		r.SystemErr = err
		return r
	}

	userUuid, err := uuid.FromBytes([]byte(auth.UserID))
	if err != nil {
		r.SystemErr = err
		return r
	}

	authTkn, err := s.authSigner.CreateAuthToken(token.CreateAuthTokenParams{
		Method:       jwt.SigningMethodRS256,
		TokenType:    token.TOKEN_TYPE_AUTHORIZATION,
		AuthUuid:     authUuid,
		UserUuid:     userUuid,
		Ttl:          s.ttl.TokenTtl,
		Applications: []string{auth.Edges.Application.Domain},
	})
	if err != nil {
		r.SystemErr = err
		return r
	}

	expiredIn := auth.ExpireAt.Sub(now).Milliseconds() / 1000

	bundle := &token.AuthTokenBundle{
		AccessToken:     authTkn,
		BundleTokenType: token.BUNDLE_TOKEN_TYPE_BEARER,
		ExpiresIn:       expiredIn,
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
