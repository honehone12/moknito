package id

import "github.com/google/uuid"

type Id string

func NewRandom() (Id, error) {
	uuid, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}

	return Id(uuid[:]), nil
}

func NewSequential() (Id, error) {
	uuid, err := uuid.NewV7()
	if err != nil {
		return "", err
	}

	return Id(uuid[:]), nil
}

func FromUUID(uuid uuid.UUID) Id {
	return Id(uuid[:])
}

func (id Id) ToUUID() (uuid.UUID, error) {
	return uuid.FromBytes([]byte(id))
}
