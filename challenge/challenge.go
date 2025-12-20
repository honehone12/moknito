package challenge

import (
	"crypto/sha256"
	"encoding/base64"
	"moknito/hash"
)

func Verify(verifier string, stored []byte) (bool, error) {
	raw, err := base64.RawURLEncoding.DecodeString(verifier)
	if err != nil {
		return false, err
	}

	h := sha256.Sum256(raw)
	return hash.BytesCheck(h[:], stored), nil
}
