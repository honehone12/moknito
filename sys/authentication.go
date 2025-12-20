package sys

import (
	"context"
	"errors"
	"moknito/ent"
	"moknito/ent/authentication"
	"moknito/id"
	"moknito/token"
	"net/http"
	"time"
)

type AuthenticationSigner interface {
	VerifyAuthentication(
		ctx context.Context,
		cookie *http.Cookie,
	) *VerifyAuthenticationResult
}

type VerifyAuthenticationResult struct {
	UserId id.Id
	AuthId id.Id
	E
}

func (s *EntRdsSys) VerifyAuthentication(
	ctx context.Context,
	cookie *http.Cookie,
) *VerifyAuthenticationResult {
	r := &VerifyAuthenticationResult{}

	claim, err := s.authSigner.Parse(cookie.Value)
	if err != nil {
		r.ValidationErr = err
		return r
	}

	authId, err := id.FromUUIDString(claim.ID)
	if err != nil {
		r.ValidationErr = err
		return r
	}
	userId, err := id.FromUUIDString(claim.Subject)
	if err != nil {
		r.ValidationErr = err
		return r
	}

	auth, err := s.ent.Authentication.Query().
		Select(
			authentication.FieldIP,
			authentication.FieldUserAgent,
			authentication.FieldUserID,
		).
		Where(
			authentication.ID(string(authId)),
			authentication.ExpireAtGT(time.Now()),
			authentication.LogoutAtIsNil(),
			authentication.DeletedAtIsNil(),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		r.ValidationErr = err
		return r
	} else if err != nil {
		r.SystemErr = err
		return r
	}

	if id.Id(auth.UserID) != userId {
		r.ValidationErr = errors.New("wrong subject")
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

func (s *EntRdsSys) createAuthentication(
	authId, userId id.Id,
) (*http.Cookie, error) {
	authUuid, err := authId.ToUUID()
	if err != nil {
		return nil, err
	}
	userUuid, err := userId.ToUUID()
	if err != nil {
		return nil, err
	}

	tkn, err := s.authSigner.CreateAuthToken(token.CreateAuthTokenParams{
		TokenType: token.TOKEN_TYPE_AUTHENTICATION,
		AuthUuid:  authUuid,
		UserUuid:  userUuid,
		Ttl:       s.ttl.TokenTtl,
	})
	if err != nil {
		return nil, err
	}

	cookie := &http.Cookie{
		Name:     AUTHENTICATED_COOKIE_KEY,
		Value:    tkn,
		Path:     "/",
		MaxAge:   int(s.ttl.TokenTtl.Seconds()),
		Secure:   false, // for local
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	if err := cookie.Valid(); err != nil {
		return nil, err
	}

	return cookie, nil
}
