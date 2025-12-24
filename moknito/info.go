package moknito

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

type InfoRequest = ApiRequest

type InfoResponse struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
}

func (m *Moknito) InfoApp(ctx echo.Context) error {
	params := InfoRequest{}

	if err := m.bind(ctx, &params); err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	r := m.system.InfoApp(
		ctx.Request().Context(),
		params.Id,
	)
	if r.SystemErr != nil {
		ctx.Logger().Error(r.SystemErr)
		return echo.ErrInternalServerError
	}
	if r.ValidationErr != nil {
		ctx.Logger().Warn(r.ValidationErr)
		return echo.ErrBadRequest
	}

	return ctx.JSON(http.StatusOK, InfoResponse{
		Name:   r.Name,
		Domain: r.Domain,
	})
}
