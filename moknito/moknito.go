package moknito

import (
	"errors"
	"moknito/ent"
	"moknito/sys"
	"os"
	"regexp"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
)

const __CTX_KEY_AUTHED_USER_ID = "AUTHED_USER_ID"
const __CTX_KEY_AUTH_ID = "AUTH_ID"

const __ORIGIN_SCHEME = "http" // for local

const __REGEX_UUID_V7 = `^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`
const __REGEX_NAME = `^[a-zA-Z0-9\s\.\-']+$`
const __REGEX_PASSWORD = `^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{}|;:'",./<>?~` + "`" + `]+$`

type ApiRequest struct {
	// client application id
	Id string `param:"id" validate:"required,len=36,uuid7"`
}

type Moknito struct {
	system    sys.Sys
	validator *validator.Validate

	origin string

	regex *RegexValidator
}

type RegexValidator struct {
	uuid7Regex    *regexp.Regexp
	nameRegex     *regexp.Regexp
	passwordRegex *regexp.Regexp
}

func NewRegexValidator() (*RegexValidator, error) {
	uuid7Regex, err := regexp.Compile(__REGEX_UUID_V7)
	if err != nil {
		return nil, err
	}
	nameRegex, err := regexp.Compile(__REGEX_NAME)
	if err != nil {
		return nil, err
	}
	passwordRegex, err := regexp.Compile(__REGEX_PASSWORD)
	if err != nil {
		return nil, err
	}

	return &RegexValidator{
		uuid7Regex,
		nameRegex,
		passwordRegex,
	}, nil
}

func (r *RegexValidator) ValidateUuidV7(f validator.FieldLevel) bool {
	return r.uuid7Regex.MatchString(f.Field().String())
}

func (r *RegexValidator) ValidateName(f validator.FieldLevel) bool {
	return r.nameRegex.MatchString(f.Field().String())
}

func (r *RegexValidator) ValidatePassword(f validator.FieldLevel) bool {
	return r.passwordRegex.MatchString(f.Field().String())
}

func NewMocknito() (*Moknito, error) {
	// don't inject other than env
	// to prevent exposing sensitive info
	// just write within module for testing

	origin := os.Getenv("ORIGIN")
	if len(origin) == 0 {
		return nil, errors.New("could not find origin env")
	}

	regex, err := NewRegexValidator()
	if err != nil {
		return nil, err
	}

	system, err := sys.NewSystem(
		sys.TtlParams{
			RegistrationTtl: time.Minute * 5,
			SessionTtl:      time.Hour,
			TokenTtl:        time.Hour * 12,
			RefreshTtl:      time.Hour * 72,
			CodeTtl:         time.Minute * 5,
		},
		ent.Debug(),
	)
	if err != nil {
		return nil, err
	}

	validator := validator.New()
	validator.RegisterValidation("uuid7", regex.ValidateUuidV7)
	validator.RegisterValidation("name", regex.ValidateName)
	validator.RegisterValidation("password", regex.ValidatePassword)

	return &Moknito{
		system,
		validator,
		origin,
		regex,
	}, nil
}

func (m *Moknito) Close() error {
	return m.system.Close()
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
