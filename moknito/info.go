package moknito

import (
	"moknito/res"
	"net/http"

	"github.com/labstack/echo/v4"
)

type InfoAppRequest struct {
	Id string `query:"id" validate:"len=36"`
}

type InfoAppResponse struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
}

func (m *Moknito) InfoApp(ctx echo.Context) error {
	query := InfoAppRequest{}

	if err := m.bind(ctx, &query); err != nil {
		ctx.Logger().Warn(err)
		return res.BadRequest(ctx)
	}

	r := m.system.InfoApp(
		ctx.Request().Context(),
		query.Id,
	)
	if r.SystemErr != nil {
		return r.SystemErr
	}
	if r.ValidationErr != nil {
		ctx.Logger().Warn(r.ValidationErr)
		return res.BadRequest(ctx)
	}

	return ctx.JSON(http.StatusOK, InfoAppResponse{
		Name:   r.Name,
		Domain: r.Domain,
	})
}
