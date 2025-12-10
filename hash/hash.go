package hash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

const HASH_LEN = 32
const SALT_LEN = 32
const PEPPER_LEN = 32
const PEPPER_ENV_LEN = 44

const __ALGORITHM = "argon2id"
const __MIN_ALGO_VERSION = 19
const __T = 3
const __M = 64 * 1024 //kb => 64mb
const __P = 4

func hash(password string, salt []byte, t, m uint32, p uint8) ([]byte, error) {
	encPepper := os.Getenv("PEPPER")
	if len(encPepper) != PEPPER_ENV_LEN {
		return nil, errors.New("pepper env is not valid")
	}
	pepper, err := base64.StdEncoding.DecodeString(encPepper)
	if err != nil {
		return nil, err
	}

	l := len(password)
	pepperPw := make([]byte, PEPPER_LEN+l)
	if n := copy(pepperPw[:PEPPER_LEN], pepper); n != PEPPER_LEN {
		return nil, errors.New("pepper length is unexpected or failed to copy")
	}
	if n := copy(pepperPw[PEPPER_LEN:], []byte(password)); n != l {
		return nil, errors.New("failed to copy password")
	}

	hash := argon2.IDKey(
		pepperPw,
		salt,
		t,
		m,
		p,
		HASH_LEN,
	)

	return hash, nil
}

func Hash(password string) (string, error) {
	salt := make([]byte, SALT_LEN)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash, err := hash(
		password,
		salt,
		__T,
		__M,
		__P,
	)
	if err != nil {
		return "", err
	}

	encHash := base64.RawStdEncoding.EncodeToString(hash)
	encSalt := base64.RawStdEncoding.EncodeToString(salt)

	pwHash := fmt.Sprintf(
		"$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		__ALGORITHM,
		argon2.Version,
		__M,
		__T,
		__P,
		encSalt,
		encHash,
	)

	return pwHash, nil
}

func check(hash, saved []byte) bool {
	if subtle.ConstantTimeEq(int32(len(hash)), int32(len(saved))) != 1 {
		return false
	}

	if subtle.ConstantTimeCompare(hash, saved) != 1 {
		return false
	}

	return true
}

func Check(password, pwHash string) (bool, error) {
	encs := strings.Split(pwHash, "$")
	if len(encs) != 6 {
		return false, errors.New("pwHash separator appears unexpected times")
	}
	if len(encs[0]) != 0 {
		return false, errors.New("pwHash has unexpected prefix")
	}

	if encs[1] != __ALGORITHM {
		return false, errors.New("hash algorithm switching is not implemented")
	}

	var v int
	if n, err := fmt.Sscanf(encs[2], "v=%d", &v); n != 1 || err != nil {
		return false, errors.New("failed to scan hash algorithm version")
	}
	if v < __MIN_ALGO_VERSION || v > argon2.Version {
		return false, errors.New("unsupported hash algorithm version")
	}

	var m, t uint32
	var p uint8
	if n, err := fmt.Sscanf(encs[3], "m=%d,t=%d,p=%d", &m, &t, &p); n != 3 || err != nil {
		return false, errors.New("failed to scan hash algorithm params")
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(encs[4])
	if err != nil {
		return false, err
	}

	saved, err := base64.RawStdEncoding.Strict().DecodeString(encs[5])
	if err != nil {
		return false, err
	}

	hash, err := hash(password, salt, t, m, p)
	if err != nil {
		return false, err
	}

	return check(hash, saved), nil
}
