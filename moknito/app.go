package moknito

import (
	"errors"
	"moknito/id"
	"moknito/res"
	"net/http"

	"github.com/labstack/echo/v4"
)

type AppAuthorizeRequest struct {
	Id string `form:"id" validate:"len=36"`
}

func (m *Moknito) AppAuthorize(ctx echo.Context) error {
	query := AppAuthorizeRequest{}

	if err := m.bind(ctx, &query); err != nil {
		ctx.Logger().Warn(err)
		return res.BadRequest(ctx)
	}

	rawUser := ctx.Get(CONTEXT_KEY_AUTHED_USER_ID)
	userId, ok := rawUser.(id.Id)
	if !ok {
		return errors.New("failed to cast ctx user id value to id")
	}

	invalid, err := m.system.AppAuthorize(
		ctx.Request().Context(),
		userId,
		query.Id,
	)
	if invalid != nil {
		ctx.Logger().Warn(err)
		return res.BadRequest(ctx)
	}
	if err != nil {
		return err
	}

	return ctx.NoContent(http.StatusOK)
}
