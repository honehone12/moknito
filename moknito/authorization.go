package moknito

import "github.com/labstack/echo/v4"

type authTokenRequest struct {
	Id       string `param:"id" validate:"len=36,uuid7"`
	Grant    string `form:"grant" validate:"oneof=code refresh"`
	Code     string `form:"code" validate:"len=22"`
	Verifier string `form:"verifier" validate:"min=43,max=256"`
	Redirect string `form:"redirect" validate:"url,max=256"`
}

func (m *Moknito) AuthToken(ctx echo.Context) error {

	return nil
}
