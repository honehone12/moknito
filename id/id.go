package id

import "github.com/google/uuid"

// 16byte string
type Id string

func NewRandom() (Id, error) {
	uuid, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}

	return FromUUID(uuid), nil
}

func NewSequential() (Id, error) {
	uuid, err := uuid.NewV7()
	if err != nil {
		return "", err
	}

	return FromUUID(uuid), nil
}

func FromUUID(uuid uuid.UUID) Id {
	return Id(uuid[:])
}

func FromUUIDString(s string) (Id, error) {
	uuid, err := uuid.Parse(s)
	if err != nil {
		return "", err
	}

	return FromUUID(uuid), nil
}

func (id Id) ToUUID() (uuid.UUID, error) {
	return uuid.FromBytes([]byte(id))
}
