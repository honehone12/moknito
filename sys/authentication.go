package sys

import (
	"context"
	"errors"
	"moknito/binid"
	"moknito/ent/authentication"

	"moknito/token"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AuthenticationSys interface {
	VerifyAuthentication(
		ctx context.Context,
		cookie *http.Cookie,
	) *VerifyAuthenticationResult
}

type VerifyAuthenticationResult struct {
	UserId binid.BinId
	AuthId binid.BinId
	E
}

func (s *System) VerifyAuthentication(
	ctx context.Context,
	cookie *http.Cookie,
) *VerifyAuthenticationResult {
	r := &VerifyAuthenticationResult{}

	claim, err := s.authSigner.Parse(token.ParseParams{
		Raw:       cookie.Value,
		Method:    jwt.SigningMethodHS256,
		TokenType: token.TOKEN_TYPE_AUTHENTICATION,
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

	ok, err := s.ent.Authentication.Query().
		// Select(
		// 	authentication.FieldIP,
		// 	authentication.FieldUserAgent,
		// ).
		Where(
			authentication.ID(authId),
			authentication.ExpireAtGT(time.Now()),
			authentication.LogoutAtIsNil(),
			authentication.DeletedAtIsNil(),
			authentication.UserID(userId),
		).
		Exist(ctx)
	if err != nil {
		r.SystemErr = err
		return r
	}
	if !ok {
		r.ValidationErr = errors.New("no active authentication found")
		return r
	}

	// we should check a.Ip and a.UserAgent
	//   same (near) country ?
	//   same os ?
	//   same browser ?
	// but they are currentry out of scope

	r.UserId = userId
	r.AuthId = authId
	return r
}

func (s *System) createAuthentication(
	authId, userId binid.BinId,
) (*http.Cookie, error) {
	tkn, err := s.authSigner.CreateAuthToken(token.CreateAuthTokenParams{
		Method:    jwt.SigningMethodHS256,
		TokenType: token.TOKEN_TYPE_AUTHENTICATION,
		AuthId:    authId,
		UserId:    userId,
		Ttl:       s.ttl.TokenTtl,
	})
	if err != nil {
		return nil, err
	}

	cookie := &http.Cookie{
		Name:     AUTHENTICATED_COOKIE_KEY,
		Value:    tkn,
		Path:     "/",
		MaxAge:   int(s.ttl.TokenTtl.Milliseconds() / 1000),
		Secure:   __SECURE_COOKIE,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	if err := cookie.Valid(); err != nil {
		return nil, err
	}

	return cookie, nil
}
