package id

import "github.com/google/uuid"

func NewRandom() (string, error) {
	uuid, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}

	return string(uuid[:]), nil
}

func NewSequential() (string, error) {
	uuid, err := uuid.NewV7()
	if err != nil {
		return "", err
	}

	return string(uuid[:]), nil
}

func ToUUID(id string) (uuid.UUID, error) {
	return uuid.ParseBytes([]byte(id))
}

func FromUUID(uuid uuid.UUID) string {
	return string(uuid[:])
}
