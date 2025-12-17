package moknito

import (
	"moknito/res"
	"net/http"

	"github.com/labstack/echo/v4"
)

type applicationInfomationRequest struct {
	Id string `query:"id" validate:"len:22,base64rawurl"`
}

type applicationInfomationResponse struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
}

func (m *Moknito) ApplicationInfomation(ctx echo.Context) error {
	query := applicationInfomationRequest{}

	if err := m.bind(ctx, &query); err != nil {
		ctx.Logger().Warn(err)
		return res.BadRequest(ctx)
	}

	app, ok, err := m.system.ApplicationInfomation(
		ctx.Request().Context(),
		query.Id,
	)
	if err != nil {
		return err
	}
	if !ok {
		ctx.Logger().Warn("application not found")
		return res.BadRequest(ctx)
	}

	return ctx.JSON(http.StatusOK, applicationInfomationResponse{
		Name:   app.Name,
		Domain: app.Domain,
	})
}
