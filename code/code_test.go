package code

import (
	"bytes"
	"testing"
)

func TestNewCode(t *testing.T) {
	t.Run("Length", func(t *testing.T) {
		c, err := NewCode()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(c) != CODE_LEN {
			t.Errorf("expected code length %d, got %d", CODE_LEN, len(c))
		}
	})

	t.Run("Uniqueness", func(t *testing.T) {
		c1, err := NewCode()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		c2, err := NewCode()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if bytes.Equal(c1, c2) {
			t.Error("expected two generated codes to be different")
		}
	})
}
