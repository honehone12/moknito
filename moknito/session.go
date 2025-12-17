package moknito

import (
	"errors"
	"moknito/res"
	"moknito/sys"
	"net/http"

	"github.com/labstack/echo/v4"
)

func (m *Moknito) SetSession() echo.MiddlewareFunc {
	return m.setSession
}

func (m *Moknito) setSession(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		cookie, err := ctx.Cookie(sys.SESSION_COOKIE_KEY)
		if errors.Is(err, http.ErrNoCookie) {
			newCookie, err := m.system.CreateSession(ctx.Request().Context())
			if err != nil {
				return err
			}

			ctx.SetCookie(newCookie)
			return next(ctx)
		} else if err != nil {
			return err
		}

		if err := m.validator.Var(cookie.Value, "min=44,base64rawurl"); err != nil {
			ctx.Logger().Warn(err)
			return res.BadRequest(ctx)
		}

		incrCookie, invalid, err := m.system.VerifySession(
			ctx.Request().Context(),
			cookie,
		)
		if invalid != nil {
			ctx.Logger().Debug(err)

			newCookie, err := m.system.CreateSession(ctx.Request().Context())
			if err != nil {
				return err
			}

			ctx.SetCookie(newCookie)
			return next(ctx)
		}
		if err != nil {
			return err
		}

		ctx.SetCookie(incrCookie)
		return next(ctx)
	}
}

func (m *Moknito) VerifySession() echo.MiddlewareFunc {
	return m.verifySession
}

func (m *Moknito) verifySession(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		cookie, err := ctx.Cookie(sys.SESSION_COOKIE_KEY)
		if errors.Is(err, http.ErrNoCookie) {
			ctx.Logger().Warn("no session cookie")
			// here might have to be Unauthorized response code,
			// but i user Forbidden because i don't want to rerun
			// WWW-Authenticate header
			return res.Forbidden(ctx)
		} else if err != nil {
			return err
		}

		// at least encoded signature 43byte+1
		if err := m.validator.Var(cookie.Value, "min=44,base64rawurl"); err != nil {
			ctx.Logger().Warn(err)
			return res.BadRequest(ctx)
		}

		newCookie, invalid, err := m.system.VerifySession(
			ctx.Request().Context(),
			cookie,
		)
		if invalid != nil {
			ctx.Logger().Warn(err)
			return res.BadRequest(ctx)
		}
		if err != nil {
			return err
		}

		ctx.SetCookie(newCookie)

		return next(ctx)
	}
}
