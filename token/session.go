package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
)

type SessionTokenSigner struct {
	key []byte
}

func NewSessionTokenSigner() (*SessionTokenSigner, error) {
	// don't inject other than env
	// to prevent exposing sensitive info
	// just write within module for testing

	encKey := os.Getenv("SESSION_TOKEN_KEY")
	if len(encKey) != SIGNATURE_KEY_ENV_LEN {
		return nil, errors.New("unexpected auth token signature key length")
	}
	key, err := base64.StdEncoding.DecodeString(encKey)
	if err != nil {
		return nil, err
	}
	if len(key) != SIGNATURE_KEY_LEN {
		return nil, errors.New("unexpected signature key length")
	}

	return &SessionTokenSigner{key}, nil
}

func (s *SessionTokenSigner) hash(sessKey []byte, nonce string) ([]byte, error) {
	hmac := hmac.New(sha256.New, s.key)
	if _, err := hmac.Write(sessKey); err != nil {
		return nil, err
	}
	if _, err := hmac.Write([]byte(nonce)); err != nil {
		return nil, err
	}

	hash := hmac.Sum(nil)
	return hash, nil
}

func (s *SessionTokenSigner) SignedCookie(sessKey []byte, nonce string) (string, error) {
	hash, err := s.hash(sessKey, nonce)
	if err != nil {
		return "", err
	}

	l := len(sessKey)
	raw := make([]byte, SIGNATURE_LEN+l)
	if n := copy(raw[:SIGNATURE_LEN], hash); n != SIGNATURE_LEN {
		return "", errors.New("failed to copy signature")
	}
	if n := copy(raw[SIGNATURE_LEN:], sessKey); n != l {
		return "", errors.New("failed to copy session key")
	}

	enc := base64.RawURLEncoding.EncodeToString(raw)
	return enc, nil
}

func (s *SessionTokenSigner) Verify(
	signatue, sessKey []byte,
	nonce string,
) (bool, error) {
	hash, err := s.hash(sessKey, nonce)
	if err != nil {
		return false, err
	}

	return hmac.Equal(signatue, hash), nil
}
