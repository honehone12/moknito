package moknito

import (
	"moknito/res"
	"net/http"

	"github.com/labstack/echo/v4"
)

type userRegisterRequest struct {
	Name     string `form:"name" validate:"min=1,max=256"`
	Email    string `form:"email" validate:"email,max=128"`
	Password string `form:"password" validate:"min=8,max=128"`
}

type userAuthenticationRequest struct {
	Email    string `form:"email" validate:"email,max=128"`
	Password string `form:"password" validate:"min=8,max=128"`
}

func (m *Moknito) UserRegister(ctx echo.Context) error {
	form := userRegisterRequest{}

	if err := m.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return res.BadRequest(ctx)
	}

	r := m.system.UserRegister(
		ctx.Request().Context(),
		form.Name,
		form.Email,
		form.Password,
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

func (m *Moknito) UserJoin(ctx echo.Context) error {
	form := userAuthenticationRequest{}

	if err := m.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return res.BadRequest(ctx)
	}

	req := ctx.Request()
	r := m.system.UserJoin(
		req.Context(),
		form.Email, form.Password,
		ctx.RealIP(), req.Header.Get("User-Agent"),
	)
	if r.SystemErr != nil {
		return r.SystemErr
	}
	if r.ValidationErr != nil {
		ctx.Logger().Warn(r.ValidationErr)
		return res.BadRequest(ctx)
	}

	ctx.SetCookie(r.Cookie)
	return ctx.NoContent(http.StatusOK)
}

func (m *Moknito) UserAuthenticate(ctx echo.Context) error {
	form := userAuthenticationRequest{}

	if err := m.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return res.BadRequest(ctx)
	}

	req := ctx.Request()
	r := m.system.UserAuthenticate(
		req.Context(),
		form.Email, form.Password,
		ctx.RealIP(), req.Header.Get("User-Agent"),
	)
	if r.SystemErr != nil {
		return r.SystemErr
	}
	if r.ValidationErr != nil {
		ctx.Logger().Warn(r.ValidationErr)
		return res.BadRequest(ctx)
	}

	ctx.SetCookie(r.Cookie)
	return ctx.NoContent(http.StatusOK)
}
