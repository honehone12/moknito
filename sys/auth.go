package sys

import (
	"errors"
	"moknito/ent"
	"moknito/ent/authentication"
	"moknito/ent/user"
	"moknito/id"
	"moknito/res"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
)

const AUTHENTICATED_COOKIE_KEY = "ae"

func (s *EntRdsSys) VerifyAuthenticatedCookie() echo.MiddlewareFunc {
	return s.verifyAuthenticatedCookie
}

func (s *EntRdsSys) verifyAuthenticatedCookie(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		cookie, err := ctx.Cookie(AUTHENTICATED_COOKIE_KEY)
		if errors.Is(err, http.ErrNoCookie) {
			ctx.Logger().Warn("no auth cookie")
			return res.Forbidden(ctx)
		} else if err != nil {
			return err
		}

		if len(cookie.Value) == 0 {
			ctx.Logger().Warn("empty auth cookie value")
			return res.BadRequest(ctx)
		}

		claim, err := s.authSigner.Parse(cookie.Value)
		if err != nil {
			ctx.Logger().Warn(err)
			return res.BadRequest(ctx)
		}

		authId, err := id.FromUUIDString(claim.ID)
		if err != nil {
			ctx.Logger().Warn(err)
			return res.BadRequest(ctx)
		}
		userId, err := id.FromUUIDString(claim.Subject)
		if err != nil {
			ctx.Logger().Warn(err)
			return res.BadRequest(ctx)
		}

		c := ctx.Request().Context()
		a, err := s.ent.Authentication.Query().
			Select(
				authentication.FieldIP,
				authentication.FieldUserAgent,
			).
			Where(
				authentication.ID(string(authId)),
				authentication.ExpireAtGT(time.Now()),
				authentication.LogoutAtIsNil(),
				authentication.DeletedAtIsNil(),
			).
			WithUser(func(q *ent.UserQuery) {
				q.Select(user.FieldID)
			}).
			Only(c)
		if ent.IsNotFound(err) {
			ctx.Logger().Warn("wrong auth id")
			return res.BadRequest(ctx)
		} else if err != nil {
			return err
		}

		if a.Edges.User.ID != string(userId) {
			ctx.Logger().Warn("wrong user id")
			return res.BadRequest(ctx)
		}

		// we should check a.Ip and a.UserAgent
		//   same country ?
		//   same os ?
		//   same browser ?
		// but they are currentry out of scope

		return next(ctx)
	}
}
