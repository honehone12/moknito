package id

import (
	"testing"

	"github.com/google/uuid"
)

func TestNewRandom(t *testing.T) {
	id, err := NewRandom()
	if err != nil {
		t.Fatalf("NewRandom() returned an unexpected error: %v", err)
	}
	if len(id) != 16 {
		t.Fatalf("Expected ID string length of 16, got %d", len(id))
	}

	byteSlice := []byte(id)
	if len(byteSlice) != 16 {
		t.Fatalf("Expected byte slice length of 16, got %d", len(byteSlice))
	}

	// Try to parse the bytes to ensure it's a valid UUID
	parsedUUID, err := ToUUID(id)
	if err != nil {
		t.Errorf("The generated ID could not be parsed as a UUID: %v. ID string length: %d, byte slice length: %d", err, len(id), len(byteSlice))
	}
	if parsedUUID == uuid.Nil {
		t.Error("The generated ID is a Nil UUID")
	}
}

func TestNewSequential(t *testing.T) {
	id, err := NewSequential()
	if err != nil {
		t.Fatalf("NewSequential() returned an unexpected error: %v", err)
	}
	if len(id) != 16 {
		t.Fatalf("Expected ID string length of 16, got %d", len(id))
	}

	byteSlice := []byte(id)
	if len(byteSlice) != 16 {
		t.Fatalf("Expected byte slice length of 16, got %d", len(byteSlice))
	}

	// Try to parse the bytes to ensure it's a valid UUID
	parsedUUID, err := ToUUID(id)
	if err != nil {
		t.Fatalf("The generated ID could not be parsed as a UUID: %v. ID string length: %d, byte slice length: %d", err, len(id), len(byteSlice))
	}
	if parsedUUID.Version() != 7 {
		t.Errorf("Expected UUID version 7, got %s", parsedUUID.Version())
	}

	// Check if sequential IDs are monotonic
	id2, err := NewSequential()
	if err != nil {
		t.Fatalf("NewSequential() returned an unexpected error on second call: %v", err)
	}
	parsedUUID2, err := ToUUID(id2)
	if err != nil {
		t.Fatalf("ToUUID failed on second sequential ID: %v", err)
	}

	if parsedUUID.Time() > parsedUUID2.Time() {
		t.Errorf("Sequential UUIDs are not monotonic. First: %v, Second: %v", parsedUUID.Time(), parsedUUID2.Time())
	}
}

func TestUUIDConversion(t *testing.T) {
	t.Run("SuccessfulRoundTrip", func(t *testing.T) {
		originalUUID, err := uuid.NewRandom()
		if err != nil {
			t.Fatalf("failed to generate UUID for test: %v", err)
		}

		idString := FromUUID(originalUUID)
		if len(idString) != 16 {
			t.Fatalf("Expected ID string length of 16, got %d", len(idString))
		}

		byteSlice := []byte(idString)
		if len(byteSlice) != 16 {
			t.Fatalf("Expected byte slice length of 16, got %d", len(byteSlice))
		}

		resultUUID, err := ToUUID(idString)
		if err != nil {
			t.Fatalf("ToUUID() returned an unexpected error: %v", err)
		}

		if originalUUID != resultUUID {
			t.Errorf("Expected UUID %s, got %s", originalUUID, resultUUID)
		}
	})

	t.Run("InvalidStringToUUID", func(t *testing.T) {
		invalidIDString := "this-is-not-a-uuid" // length is 20
		_, err := ToUUID(invalidIDString)
		if err == nil {
			t.Error("ToUUID() did not return an error for an invalid ID string")
		}
	})
}