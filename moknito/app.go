package moknito

import (
	"errors"
	"fmt"
	"moknito/id"
	"moknito/res"
	"net/http"

	"github.com/labstack/echo/v4"
)

type AppAllowRequest struct {
	Id string `form:"id" validate:"len=36"`
}

type AppAuthorizeRequest struct {
	Id        string `form:"id" validate:"len=36"`
	Challenge string `form:"challenge" validate:"len=22,base64rawurl"`
}

func (m *Moknito) AppAllow(ctx echo.Context) error {
	form := AppAllowRequest{}

	if err := m.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return res.BadRequest(ctx)
	}

	rawUser := ctx.Get(CONTEXT_KEY_AUTHED_USER_ID)
	userId, ok := rawUser.(id.Id)
	if !ok {
		return errors.New("failed to cast ctx user id value to id")
	}

	r := m.system.AppAllow(
		ctx.Request().Context(),
		userId,
		form.Id,
	)
	if r.SystemErr != nil {
		return r.SystemErr
	}
	if r.ValidationErr != nil {
		ctx.Logger().Warn(r.ValidationErr)
		return res.BadRequest(ctx)
	}

	return ctx.NoContent(http.StatusOK)
}

func (m *Moknito) AppAuthorize(ctx echo.Context) error {
	form := AppAuthorizeRequest{}

	if err := m.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return res.BadRequest(ctx)
	}

	rawUser := ctx.Get(CONTEXT_KEY_AUTHED_USER_ID)
	userId, ok := rawUser.(id.Id)
	if !ok {
		return errors.New("failed to cast ctx user id value to id")
	}

	r := m.system.AppAuthorize(
		ctx.Request().Context(),
		userId,
		form.Id,
		form.Challenge,
	)

	if r.SystemErr != nil {
		return r.SystemErr
	}
	if r.ValidationErr != nil {
		ctx.Logger().Warn(r.ValidationErr)
		return res.BadRequest(ctx)
	}

	redirect := fmt.Sprintf(
		"%s?code=%s",
		r.Redirect,
		r.Code,
	)

	ctx.Response().Header().Set("Location", redirect)
	return ctx.NoContent(http.StatusSeeOther)
}
