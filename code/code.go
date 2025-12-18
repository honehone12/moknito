package code

import (
	"crypto/rand"
)

const ENCODED_CODE_LEN = 24
const CODE_LEN = 16

func NewCode() ([]byte, error) {
	code := make([]byte, CODE_LEN)
	if _, err := rand.Read(code); err != nil {
		return nil, err
	}

	return code, nil
}
