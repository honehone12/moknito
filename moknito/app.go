package moknito

import (
	"errors"
	"fmt"
	"moknito/id"
	"moknito/sys"
	"net/http"

	"github.com/labstack/echo/v4"
)

type AppAllowRequest = ApiRequest

type AppAuthorizeRequest = ApiRequest

func (m *Moknito) AppAllow(ctx echo.Context) error {
	params := AppAllowRequest{}

	if err := m.bind(ctx, &params); err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	rawUser := ctx.Get(__CTX_KEY_AUTHED_USER_ID)
	userId, ok := rawUser.(id.Id)
	if !ok {
		return errors.New("failed to cast ctx user id value to id")
	}

	r := m.system.AppAllow(
		ctx.Request().Context(),
		userId,
		params.Id,
	)
	if r.SystemErr != nil {
		return r.SystemErr
	}
	if r.ValidationErr != nil {
		ctx.Logger().Warn(r.ValidationErr)
		return echo.ErrBadRequest
	}

	return ctx.NoContent(http.StatusOK)
}

func (m *Moknito) AppAuthorize(ctx echo.Context) error {
	params := AppAuthorizeRequest{}

	if err := m.bind(ctx, &params); err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	rawUser := ctx.Get(__CTX_KEY_AUTHED_USER_ID)
	userId, ok := rawUser.(id.Id)
	if !ok {
		return errors.New("failed to cast ctx user id")
	}

	rawAuth := ctx.Get(__CTX_KEY_AUTH_ID)
	authId, ok := rawAuth.(id.Id)
	if !ok {
		return errors.New("failed to cast ctx auth id")
	}

	r := m.system.AppAuthorize(
		ctx.Request().Context(),
		sys.AppAuthorizeParams{
			UserId:  userId,
			AuthId:  authId,
			AppUuid: params.Id,
		},
	)

	if r.SystemErr != nil {
		return r.SystemErr
	}
	if r.ValidationErr != nil {
		ctx.Logger().Warn(r.ValidationErr)
		return echo.ErrBadRequest
	}

	redirect := fmt.Sprintf(
		"%s?code=%s",
		r.Redirect,
		r.Code,
	)

	ctx.Response().Header().Set("Location", redirect)
	return ctx.NoContent(http.StatusSeeOther)
}
