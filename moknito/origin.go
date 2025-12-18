package moknito

import (
	"moknito/res"

	"github.com/labstack/echo/v4"
)

func (m *Moknito) OriginGuard() echo.MiddlewareFunc {
	return m.originGuard
}

func (m *Moknito) originGuard(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		reqOrigin := ctx.Request().Header.Get("Origin")
		if len(reqOrigin) == 0 {
			ctx.Logger().Warn("empty origin header")
			return res.BadRequest(ctx)
		}
		if reqOrigin != m.origin {
			ctx.Logger().Warnf("invalid origin header: %s", reqOrigin)
			return res.BadRequest(ctx)
		}

		return next(ctx)
	}
}
