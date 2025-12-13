package moknito

type authenticationLoginRequest struct {
	Email    string `form:"email" validate:"email,max=128"`
	Password string `form:"password" validate:"min=8,max=128"`
}
