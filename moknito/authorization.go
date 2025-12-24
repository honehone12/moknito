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
	Grant    string `form:"grant" validate:"oneof=code refresh"`
	Code     string `form:"code" validate:"len=22,base64rawurl"`
	Verifier string `form:"verifier" validate:"min=43,max=256,base64rawurl"`
	Redirect string `form:"redirect" validate:"url,max=256"`
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

	var r *sys.AuthTokenResult
	switch form.Grant {
	case "code":
		r = m.system.AuthTokenCode(
			ctx.Request().Context(),
			sys.AuthTokenCodeParams{
				AuthTokenParams: sys.AuthTokenParams{
					ApplicationId: appId,
				},
				Code:     form.Code,
				Verifier: form.Verifier,
				Redirect: form.Redirect,
			},
		)
	case "refresh":
	default:
		ctx.Logger().Warn("unknown grant type")
		return echo.ErrBadRequest
	}
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
