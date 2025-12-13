package middleware

import (
	"errors"
	"moknito/res"
	"os"

	"github.com/labstack/echo/v4"
)

var __ORIGIN string

func OriginGuard() (echo.MiddlewareFunc, error) {
	// don't inject other than env
	// to prevent exposing sensitive info
	// just write within module for testing

	__ORIGIN = os.Getenv("ORIGIN")
	if len(__ORIGIN) == 0 {
		return nil, errors.New("could not find origin env")
	}

	return originGuard, nil
}

func originGuard(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		reqOrigin := ctx.Request().Header.Get("Origin")
		if len(reqOrigin) == 0 {
			ctx.Logger().Warn("empty origin header")
			return res.BadRequest(ctx)
		}
		if reqOrigin != __ORIGIN {
			ctx.Logger().Warnf("invalid origin header: %s", reqOrigin)
			return res.BadRequest(ctx)
		}

		return next(ctx)
	}
}
