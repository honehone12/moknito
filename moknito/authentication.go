package moknito

import (
	"errors"
	"moknito/res"
	"moknito/sys"
	"net/http"

	"github.com/labstack/echo/v4"
)

func (m *Moknito) VerifyAuthentication() echo.MiddlewareFunc {
	return m.verifyAuthentication
}

func (m *Moknito) verifyAuthentication(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		cookie, err := ctx.Cookie(sys.AUTHENTICATED_COOKIE_KEY)
		if errors.Is(err, http.ErrNoCookie) {
			ctx.Logger().Warn("no auth cookie")
			// here might have to be Unauthorized response code,
			// but i user Forbidden because i don't want to rerun
			// WWW-Authenticate header
			return res.Forbidden(ctx)
		} else if err != nil {
			return err
		}

		// at least encoded signature 43byte+1
		if err := m.validator.Var(cookie.Value, "min=44,jwt"); err != nil {
			ctx.Logger().Warn(err)
			return res.BadRequest(ctx)
		}

		r := m.system.VerifyAuthentication(
			ctx.Request().Context(),
			cookie,
		)
		if r.SystemErr != nil {
			return r.SystemErr
		}
		if r.ValidationErr != nil {
			ctx.Logger().Warn(r.ValidationErr)
			return res.BadRequest(ctx)
		}

		ctx.Set(CONTEXT_KEY_AUTHED_USER_ID, r.UserId)

		return next(ctx)
	}
}
