package moknito

import (
	"context"
	"moknito/ent"
	"net/http"
)

type MockSys struct {
	// SessionSigner
	CreateSessionFunc func(ctx context.Context) (*http.Cookie, error)
	IncrSessionFunc   func(ctx context.Context, sessKey []byte) (*http.Cookie, error)
	VerifySessionFunc func(ctx context.Context, cookie *http.Cookie) (*http.Cookie, error, error)

	// AuthSigner
	VerifyAuthenticationFunc func(ctx context.Context, cookie *http.Cookie) (error, error)

	// UserSys
	UserRegisterFunc     func(ctx context.Context, name, email, password string) (bool, error)
	UserJoinFunc         func(ctx context.Context, email, password, ip, userAgent string) (*http.Cookie, bool, error)
	UserAuthenticateFunc func(ctx context.Context, email, password, ip, userAgent string) (*http.Cookie, bool, error)

	// AppSys
	ApplicationInfomationFunc func(ctx context.Context, id string) (*ent.Application, bool, error)
}

func (m *MockSys) CreateSession(ctx context.Context) (*http.Cookie, error) {
	if m.CreateSessionFunc != nil {
		return m.CreateSessionFunc(ctx)
	}
	return nil, nil
}

func (m *MockSys) IncrSession(ctx context.Context, sessKey []byte) (*http.Cookie, error) {
	if m.IncrSessionFunc != nil {
		return m.IncrSessionFunc(ctx, sessKey)
	}
	return nil, nil
}

func (m *MockSys) VerifySession(ctx context.Context, cookie *http.Cookie) (*http.Cookie, error, error) {
	if m.VerifySessionFunc != nil {
		return m.VerifySessionFunc(ctx, cookie)
	}
	return nil, nil, nil
}

func (m *MockSys) VerifyAuthentication(ctx context.Context, cookie *http.Cookie) (error, error) {
	if m.VerifyAuthenticationFunc != nil {
		return m.VerifyAuthenticationFunc(ctx, cookie)
	}
	return nil, nil
}

func (m *MockSys) UserRegister(ctx context.Context, name, email, password string) (bool, error) {
	if m.UserRegisterFunc != nil {
		return m.UserRegisterFunc(ctx, name, email, password)
	}
	return false, nil
}

func (m *MockSys) UserJoin(ctx context.Context, email, password, ip, userAgent string) (*http.Cookie, bool, error) {
	if m.UserJoinFunc != nil {
		return m.UserJoinFunc(ctx, email, password, ip, userAgent)
	}
	return nil, false, nil
}

func (m *MockSys) UserAuthenticate(ctx context.Context, email, password, ip, userAgent string) (*http.Cookie, bool, error) {
	if m.UserAuthenticateFunc != nil {
		return m.UserAuthenticateFunc(ctx, email, password, ip, userAgent)
	}
	return nil, false, nil
}

func (m *MockSys) ApplicationInfomation(ctx context.Context, id string) (*ent.Application, bool, error) {
	if m.ApplicationInfomationFunc != nil {
		return m.ApplicationInfomationFunc(ctx, id)
	}
	return nil, false, nil
}

func (m *MockSys) Close() error {
	return nil
}
