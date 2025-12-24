package moknito

import (
	"errors"
	"moknito/sys"
	"net/http"

	"github.com/labstack/echo/v4"
)

// set new session when session is not valid
func (m *Moknito) SetSession() echo.MiddlewareFunc {
	return m.setSession
}

func (m *Moknito) setNewSession(ctx echo.Context) error {
	newCookie, err := m.system.CreateSession(ctx.Request().Context())
	if err != nil {
		return err
	}

	ctx.SetCookie(newCookie)
	return nil
}

func (m *Moknito) setSession(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		cookie, err := ctx.Cookie(sys.SESSION_COOKIE_KEY)
		if errors.Is(err, http.ErrNoCookie) {
			m.setNewSession(ctx)
			return next(ctx)
		} else if err != nil {
			ctx.Logger().Error(err)
			return echo.ErrInternalServerError
		}

		if err := m.validator.Var(cookie.Value, "min=44,base64rawurl"); err != nil {
			ctx.Logger().Debug(err)
			m.setNewSession(ctx)
			return next(ctx)
		}

		c := ctx.Request().Context()
		r := m.system.VerifySession(c, cookie)
		if r.SystemErr != nil {
			ctx.Logger().Error(r.SystemErr)
			return echo.ErrInternalServerError
		}
		if r.ValidationErr != nil {
			ctx.Logger().Debug(r.ValidationErr)
			m.setNewSession(ctx)
			return next(ctx)
		}

		incrCookie, err := m.system.IncrSession(c, r.SessionKey)
		if err != nil {
			ctx.Logger().Error(err)
			return echo.ErrInternalServerError
		}
		ctx.SetCookie(incrCookie)
		return next(ctx)
	}
}

// fail when session is not valid
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
			return echo.ErrForbidden
		} else if err != nil {
			ctx.Logger().Error(err)
			return echo.ErrInternalServerError
		}

		// at least encoded signature 43byte+1
		if err := m.validator.Var(cookie.Value, "min=44,base64rawurl"); err != nil {
			ctx.Logger().Warn(err)
			return echo.ErrBadRequest
		}

		c := ctx.Request().Context()
		r := m.system.VerifySession(c, cookie)
		if r.SystemErr != nil {
			ctx.Logger().Error(r.SystemErr)
			return echo.ErrInternalServerError
		}
		if r.ValidationErr != nil {
			ctx.Logger().Warn(r.ValidationErr)
			return echo.ErrBadRequest
		}

		incrCookie, err := m.system.IncrSession(c, r.SessionKey)
		if err != nil {
			ctx.Logger().Error(err)
			return echo.ErrInternalServerError
		}
		ctx.SetCookie(incrCookie)

		return next(ctx)
	}
}
