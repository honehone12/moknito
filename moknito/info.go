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

	app, invalid, err := m.system.InfoApp(
		ctx.Request().Context(),
		query.Id,
	)
	if invalid != nil {
		ctx.Logger().Warn(invalid)
		return res.BadRequest(ctx)
	}
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, InfoAppResponse{
		Name:   app.Name,
		Domain: app.Domain,
	})
}
