package main

import (
	"moknito/res"
	"net/http"

	"github.com/labstack/echo/v4"
)

type userNewRequest struct {
	Name     string `form:"name" validate:"min=1,max=256"`
	Email    string `form:"email" validate:"email"`
	Password string `form:"password" validate:"min=8,max=128"`
}

type userNewResponse struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func (m *Moknito) userNew(ctx echo.Context) error {
	form := userNewRequest{}

	if err := ctx.Bind(&form); err != nil {
		ctx.Logger().Warn(err)
		return res.BadRequest(ctx)
	}

	if err := m.validator.Struct(&form); err != nil {
		ctx.Logger().Warn(err)
		return res.BadRequest(ctx)
	}

	u, err := m.system.CreateUser(
		ctx.Request().Context(),
		form.Name,
		form.Email,
		form.Password,
	)
	if err != nil {
		ctx.Logger().Error(err)
		return res.InternalError(ctx)
	}

	res := userNewResponse{
		Name:  u.Name,
		Email: u.Email,
	}
	return ctx.JSON(http.StatusOK, res)
}
