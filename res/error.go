package res

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func BadRequest(ctx echo.Context) error {
	return ctx.String(http.StatusBadRequest, "bad request")
}

func Forbidden(ctx echo.Context) error {
	return ctx.String(http.StatusForbidden, "forbidden")
}

func Unauthorized(ctx echo.Context) error {
	return ctx.String(http.StatusUnauthorized, "unauthorized")
}
