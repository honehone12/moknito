package moknito

import (
	"fmt"
	"moknito/binid"
	"moknito/sys"
	"net/http"

	"github.com/labstack/echo/v4"
)

type AuthTokenRequest struct {
	ApiRequest
	Grant    string `form:"grant" validate:"required,oneof=code refresh"`
	Code     string `form:"code" validate:"required,len=22,base64rawurl"`
	Verifier string `form:"verifier" validate:"required,min=43,max=256,base64rawurl"`
	Redirect string `form:"redirect" validate:"required,url,max=256"`
}

type AuthRefreshRequest struct {
	ApiRequest
	Grant string `form:"grant" validate:"required,oneof=code refresh"`
	Token string `form:"token" validate:"min=44,jwt"`
}

func (m *Moknito) AuthToken(ctx echo.Context) error {
	form := AuthTokenRequest{}

	if err := m.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	appId, err := binid.FromUUIDString(form.Id)
	if err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	if form.Grant != "code" {
		ctx.Logger().Warn("unsupported grant type")
		return echo.ErrBadRequest
	}

	r := m.system.AuthToken(
		ctx.Request().Context(),
		sys.AuthTokenParams{
			AuthParams: sys.AuthParams{
				ApplicationId: appId,
			},
			Code:     form.Code,
			Verifier: form.Verifier,
			Redirect: form.Redirect,
		},
	)
	if r.SystemErr != nil {
		ctx.Logger().Error(r.SystemErr)
		return echo.ErrInternalServerError
	}
	if r.ValidationErr != nil {
		ctx.Logger().Warn(r.ValidationErr)
		return echo.ErrBadRequest
	}

	origin := fmt.Sprintf("%s://%s", __ORIGIN_SCHEME, r.Domain)

	h := ctx.Response().Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Add("Vary", "Origin")
	return ctx.JSON(http.StatusOK, r.Token)
}

func (m *Moknito) AuthRefresh(ctx echo.Context) error {
	form := AuthRefreshRequest{}

	if err := m.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	appId, err := binid.FromUUIDString(form.Id)
	if err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	if form.Grant != "refresh" {
		ctx.Logger().Warn("unsupported grant type")
		return echo.ErrBadRequest
	}

	r := m.system.AuthRefresh(
		ctx.Request().Context(),
		sys.AuthRefreshParams{
			AuthParams: sys.AuthParams{
				ApplicationId: appId,
			},
			Token: form.Token,
		},
	)
	if r.SystemErr != nil {
		ctx.Logger().Error(r.SystemErr)
		return echo.ErrInternalServerError
	}
	if r.ValidationErr != nil {
		ctx.Logger().Warn(r.ValidationErr)
		return echo.ErrBadRequest
	}

	origin := fmt.Sprintf("%s://%s", __ORIGIN_SCHEME, r.Domain)

	h := ctx.Response().Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Add("Vary", "Origin")
	return ctx.JSON(http.StatusOK, r.Token)
}
