package moknito

import (
	"moknito/binid"
	"moknito/challenge"
	"moknito/sys"
	"net/http"

	"github.com/labstack/echo/v4"
)

type UserRegisterRequest struct {
	ApiRequest
	Name     string `form:"name" validate:"name,min=1,max=256"`
	Email    string `form:"email" validate:"email,max=128"`
	Password string `form:"password" validate:"password,min=8,max=128"`
}

type UserAuthenticationRequest struct {
	ApiRequest
	Email           string `form:"email" validate:"email,max=128"`
	Password        string `form:"password" validate:"password,min=8,max=128"`
	Challenge       string `form:"challenge" validate:"len=43,base64rawurl"`
	ChallengeMethod string `form:"challenge_method" validate:"oneof=plain S256"`
	Redirect        string `form:"redirect" validate:"url,max=256"`
}

type UserJoinRequest = UserAuthenticationRequest

func (m *Moknito) UserRegister(ctx echo.Context) error {
	form := UserRegisterRequest{}

	if err := m.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	r := m.system.UserRegister(
		ctx.Request().Context(),
		sys.UserRegisterParams{
			Name:     form.Name,
			Email:    form.Email,
			Password: form.Password,
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

	return ctx.NoContent(http.StatusOK)
}

func (m *Moknito) UserJoin(ctx echo.Context) error {
	form := UserJoinRequest{}

	if err := m.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	if form.ChallengeMethod != challenge.CHALLENGE_METHOD_S256 {
		ctx.Logger().Warn("unsupported challenge method")
		return echo.ErrBadRequest
	}

	appId, err := binid.FromUUIDString(form.Id)
	if err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	req := ctx.Request()
	r := m.system.UserJoin(
		req.Context(),
		sys.UserJoinParams{
			ApplicationId: appId,
			Email:         form.Email,
			Password:      form.Password,
			Challenge:     form.Challenge,
			Redirect:      form.Redirect,
			Ip:            ctx.RealIP(),
			UserAgent:     req.Header.Get("User-Agent"),
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

	ctx.SetCookie(r.Cookie)
	return ctx.NoContent(http.StatusOK)
}

func (m *Moknito) UserAuthenticate(ctx echo.Context) error {
	form := UserAuthenticationRequest{}

	if err := m.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	if form.ChallengeMethod != challenge.CHALLENGE_METHOD_S256 {
		ctx.Logger().Warn("unsupported challenge method")
		return echo.ErrBadRequest
	}

	appId, err := binid.FromUUIDString(form.Id)
	if err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	req := ctx.Request()
	r := m.system.UserAuthenticate(
		req.Context(),
		sys.UserAuthenticateParams{
			ApplicationId: appId,
			Email:         form.Email,
			Password:      form.Password,
			Challenge:     form.Challenge,
			Redirect:      form.Redirect,
			Ip:            ctx.RealIP(),
			UserAgent:     req.Header.Get("User-Agent"),
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

	ctx.SetCookie(r.Cookie)
	return ctx.NoContent(http.StatusOK)
}
