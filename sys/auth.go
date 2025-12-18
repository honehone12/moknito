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

const AUTHENTICATED_COOKIE_KEY = "ae"

// (!) return user id, verification error, system error (!)
func (s *EntRdsSys) VerifyAuthentication(
	ctx context.Context,
	cookie *http.Cookie,
) (id.Id, error, error) {
	claim, err := s.authSigner.Parse(cookie.Value)
	if err != nil {
		return "", err, nil
	}

	authId, err := id.FromUUIDString(claim.ID)
	if err != nil {
		return "", err, nil
	}
	userId, err := id.FromUUIDString(claim.Subject)
	if err != nil {
		return "", err, nil
	}

	a, err := s.ent.Authentication.Query().
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
		return "", err, nil
	} else if err != nil {
		return "", nil, err
	}

	id := id.Id(a.UserID)
	if id != userId {
		return "", errors.New("wrong subject"), nil
	}

	// we should check a.Ip and a.UserAgent
	//   same (near) country ?
	//   same os ?
	//   same browser ?
	// but they are currentry out of scope

	return id, nil, nil
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

	tkn, err := s.authSigner.CreateAuthToken(
		token.TOKEN_TYPE_AUTHENTICATION,
		authUuid.String(),
		userUuid.String(),
		s.tokenTtl,
	)
	if err != nil {
		return nil, err
	}

	cookie := &http.Cookie{
		Name:     AUTHENTICATED_COOKIE_KEY,
		Value:    tkn,
		Path:     "/",
		MaxAge:   int(s.tokenTtl.Seconds()),
		Secure:   false, // for local
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	if err := cookie.Valid(); err != nil {
		return nil, err
	}

	return cookie, nil
}
