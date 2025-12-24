package binid

import (
	"database/sql/driver"
	"errors"

	"github.com/google/uuid"
)

type BinId [16]byte

func NewRandom() (BinId, error) {
	uuid, err := uuid.NewRandom()
	if err != nil {
		return BinId{}, err
	}

	return BinId(uuid), nil
}

func NewSequential() (BinId, error) {
	uuid, err := uuid.NewV7()
	if err != nil {
		return BinId{}, err
	}

	return BinId(uuid), nil
}

func FromUUIDString(s string) (BinId, error) {
	uuid, err := uuid.Parse(s)
	if err != nil {
		return BinId{}, err
	}

	return BinId(uuid), nil
}

func (id BinId) String() string {
	uuid := uuid.UUID(id)
	return uuid.String()
}

func (id *BinId) Scan(value any) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("id supports only []byte for sanning")
	}
	if len(b) != 16 {
		return errors.New("invalid length for id")
	}

	copy(id[:], b)
	return nil
}

func (id BinId) Value() (driver.Value, error) {
	return id[:], nil
}
