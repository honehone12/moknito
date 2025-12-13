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

type userConfirmResponse struct {
	Name string `json:"name"`
}

func (m *Moknito) UserRegister(ctx echo.Context) error {
	form := userRegisterRequest{}

	if err := ctx.Bind(&form); err != nil {
		ctx.Logger().Warn(err)
		return res.BadRequest(ctx)
	}

	if err := m.validator.Struct(&form); err != nil {
		ctx.Logger().Warn(err)
		return res.BadRequest(ctx)
	}

	ok, err := m.system.RegisterUser(
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

	ctx.Response().Header().Set("Location", "/user/confirm")
	return ctx.NoContent(http.StatusSeeOther)
}

func (m *Moknito) UserConfirm(ctx echo.Context) error {
	form := authenticationLoginRequest{}

	if err := ctx.Bind(&form); err != nil {
		ctx.Logger().Warn(err)
		return res.BadRequest(ctx)
	}

	if err := m.validator.Struct(&form); err != nil {
		ctx.Logger().Warn(err)
		return res.BadRequest(ctx)
	}

	user, ok, err := m.system.ConfirmUser(
		ctx.Request().Context(),
		form.Email,
		form.Password,
	)
	if err != nil {
		ctx.Logger().Error(err)
		return res.InternalError(ctx)
	}
	if !ok {
		ctx.Logger().Warn("wrong password")
		return res.BadRequest(ctx)
	}

	return ctx.JSON(http.StatusOK, userConfirmResponse{
		Name: user.Name,
	})
}
