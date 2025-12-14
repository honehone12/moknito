package moknito

import (
	"moknito/id"
	"moknito/res"
	"moknito/token"
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

func (m *Moknito) bind(ctx echo.Context, target any) error {
	if err := ctx.Bind(target); err != nil {
		return err
	}

	if err := m.validator.Struct(target); err != nil {
		return err
	}

	return nil
}

func (m *Moknito) UserRegister(ctx echo.Context) error {
	form := userRegisterRequest{}

	if err := m.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return res.BadRequest(ctx)
	}

	ok, err := m.system.UserRegister(
		ctx.Request().Context(),
		form.Name,
		form.Email,
		form.Password,
	)
	if err != nil {
		ctx.Logger().Error(err)
		return res.InternalError(ctx)
	}
	if !ok {
		ctx.Logger().Warn("duplicated user")
		return res.BadRequest(ctx)
	}

	ctx.Response().Header().Set("Location", "/user/authenticate")
	return ctx.NoContent(http.StatusSeeOther)
}

func (m *Moknito) UserJoin(ctx echo.Context) error {
	form := userAuthenticationRequest{}

	if err := m.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return res.BadRequest(ctx)
	}

	req := ctx.Request()
	authId, ok, err := m.system.UserJoin(
		req.Context(),
		form.Email, form.Password,
		ctx.RealIP(), req.Header.Get("User-Agent"),
		m.tokenTtl,
	)
	if err != nil {
		ctx.Logger().Error(err)
		return res.InternalError(ctx)
	}
	if !ok {
		ctx.Logger().Warn("wrong credentials")
		return res.BadRequest(ctx)
	}

	if err := m.setAuthenticatedCookie(ctx, authId, form.Email); err != nil {
		ctx.Logger().Error(err)
		return res.InternalError(ctx)
	}

	ctx.Response().Header().Set("Location", "/")
	return ctx.NoContent(http.StatusSeeOther)
}

func (m *Moknito) UserAuthenticate(ctx echo.Context) error {
	form := userAuthenticationRequest{}

	if err := m.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return res.BadRequest(ctx)
	}

	req := ctx.Request()
	authId, ok, err := m.system.UserAuthenticate(
		req.Context(),
		form.Email, form.Password,
		ctx.RealIP(), req.Header.Get("User-Agent"),
		m.tokenTtl,
	)
	if err != nil {
		ctx.Logger().Error(err)
		return res.InternalError(ctx)
	}
	if !ok {
		ctx.Logger().Warn("wrong credentials")
		return res.BadRequest(ctx)
	}

	if err := m.setAuthenticatedCookie(ctx, authId, form.Email); err != nil {
		ctx.Logger().Error(err)
		return res.InternalError(ctx)
	}

	ctx.Response().Header().Set("Location", "/")
	return ctx.NoContent(http.StatusSeeOther)
}

func (m *Moknito) setAuthenticatedCookie(
	ctx echo.Context,
	id id.Id,
	email string,
) error {
	signer, err := token.NewAuthTokenSigner()
	if err != nil {
		return err
	}
	uuid, err := id.ToUUID()
	if err != nil {
		return err
	}

	tkn, err := signer.CreateAuthenticatedToken(
		uuid.String(),
		email,
		m.tokenTtl,
	)
	if err != nil {
		return err
	}

	cookie := http.Cookie{
		Name:     token.AUTHENTICATED_COOKIE_KEY,
		Value:    tkn,
		Path:     "/",
		MaxAge:   86400, // a day
		Secure:   false, // for local
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	ctx.SetCookie(&cookie)

	return nil
}
