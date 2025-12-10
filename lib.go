package main

import (
	"moknito/entity"
	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
)

type Moknito struct {
	entity    *entity.Entity
	validator *validator.Validate
}

func NewMocknito() (*Moknito, error) {
	entity, err := entity.NewEntity()
	if err != nil {
		return nil, err
	}

	validator := validator.New()

	return &Moknito{
		entity,
		validator,
	}, nil
}

func (m *Moknito) Close() error {
	return m.entity.Close()
}

type UserNewRequest struct {
	Name     string `form:"name" validate:"min=1,max=256"`
	Email    string `form:"email" validate:"email"`
	Password string `form:"password" validate:"min=8,max=128"`
}

type UserNewResponse struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func (m *Moknito) userNew(ctx echo.Context) error {
	form := UserNewRequest{}

	if err := ctx.Bind(&form); err != nil {
		ctx.Logger().Warn(err)
		return BadRequest(ctx)
	}

	if err := m.validator.Struct(&form); err != nil {
		ctx.Logger().Warn(err)
		return BadRequest(ctx)
	}

	u, err := m.entity.CreateUser(
		ctx.Request().Context(),
		form.Name,
		form.Email,
		form.Password,
	)
	if err != nil {
		ctx.Logger().Error(err)
		return InternalError(ctx)
	}

	res := UserNewResponse{
		Name:  u.Name,
		Email: u.Email,
	}
	return ctx.JSON(http.StatusOK, res)
}
