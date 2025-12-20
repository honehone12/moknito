package moknito

import (
	"moknito/res"
	"moknito/sys"
	"net/http"

	"github.com/labstack/echo/v4"
)

type userRegisterRequest struct {
	apiRequest
	Name     string `form:"name" validate:"min=1,max=256"`
	Email    string `form:"email" validate:"email,max=128"`
	Password string `form:"password" validate:"min=8,max=128"`
}

type userAuthenticationRequest struct {
	apiRequest
	Email    string `form:"email" validate:"email,max=128"`
	Password string `form:"password" validate:"min=8,max=128"`
	// ChallengeMethod string `form:"challenge_method" validate:"oneof=plain S256"`
	Challenge string `form:"challenge" validate:"len=43,base64rawurl"`
	// Redirect        string `form:"redirect" validate:"url,max=256"`
}

type userJoinRequest = userAuthenticationRequest

func (m *Moknito) UserRegister(ctx echo.Context) error {
	form := userRegisterRequest{}

	if err := m.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return res.BadRequest(ctx)
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
		return r.SystemErr
	}
	if r.ValidationErr != nil {
		ctx.Logger().Warn(r.ValidationErr)
		return res.BadRequest(ctx)
	}

	return ctx.NoContent(http.StatusOK)
}

func (m *Moknito) UserJoin(ctx echo.Context) error {
	form := userJoinRequest{}

	if err := m.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return res.BadRequest(ctx)
	}

	req := ctx.Request()
	r := m.system.UserJoin(
		req.Context(),
		sys.UserJoinParams{
			Email:     form.Email,
			Password:  form.Password,
			Challenge: form.Challenge,
			Ip:        ctx.RealIP(),
			UserAgent: req.Header.Get("User-Agent"),
		},
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
		sys.UserAuthenticateParams{
			Email:     form.Email,
			Password:  form.Password,
			Challenge: form.Challenge,
			Ip:        ctx.RealIP(),
			UserAgent: req.Header.Get("User-Agent"),
		},
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
