package hash

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// TestMain sets up the environment for the tests by creating and setting a
// PEPPER environment variable, which is required by the hash functions.
// It cleans up the environment variable after the tests have run.
func TestMain(m *testing.M) {
	// Setup: generate and set a random pepper for the test run.
	pepper := make([]byte, PEPPER_LEN)
	if _, err := rand.Read(pepper); err != nil {
		// Panic because tests cannot run without a valid pepper.
		panic("failed to generate pepper for tests: " + err.Error())
	}
	// The hash function expects a base64 encoded string.
	encPepper := base64.StdEncoding.EncodeToString(pepper)
	os.Setenv("PEPPER", encPepper)

	// Run all tests.
	exitCode := m.Run()

	// Teardown: unset the environment variable to clean up.
	os.Unsetenv("PEPPER")

	os.Exit(exitCode)
}

// TestHashAndCheck verifies the core functionality: hashing a password
// and then checking it for correctness. It also tests that an incorrect
// password does not match.
func TestHashAndCheck(t *testing.T) {
	password := "my-secret-password-!@#$"

	// 1. Test successful hashing.
	hashedPassword, err := Hash(password)
	if err != nil {
		t.Fatalf("Hash() returned an unexpected error: %v", err)
	}
	if !strings.HasPrefix(hashedPassword, "$argon2id$") {
		t.Errorf("Hashed password does not have the expected argon2id prefix. Got: %s", hashedPassword)
	}

	// 2. Test that a correct password passes the check.
	match, err := Check(password, hashedPassword)
	if err != nil {
		t.Fatalf("Check() with correct password returned an unexpected error: %v", err)
	}
	if !match {
		t.Error("Check() returned false for a correct password, want true")
	}

	// 3. Test that an incorrect password fails the check.
	wrongPassword := "not-my-password-at-all"
	match, err = Check(wrongPassword, hashedPassword)
	if err != nil {
		t.Fatalf("Check() with wrong password returned an unexpected error: %v", err)
	}
	if match {
		t.Error("Check() returned true for an incorrect password, want false")
	}
}

// TestCheckFailures tests various malformed and invalid hash strings to ensure
// the Check function handles errors gracefully and correctly identifies invalid formats.
func TestCheckFailures(t *testing.T) {
	password := "any-password"

	testCases := []struct {
		name          string
		hash          string
		expectedError string
	}{
		{
			name:          "InvalidSeparatorCount",
			hash:          "$argon2id$v=19",
			expectedError: "pwHash separator appears unexpected times",
		},
		{
			name:          "UnexpectedPrefix",
			hash:          "invalid-prefix$argon2id$v=19$m=65536,t=3,p=4$c2FsdA==$aGFzaA==",
			expectedError: "pwHash has unexpected prefix",
		},
		{
			name:          "WrongAlgorithm",
			hash:          "$scrypt$v=19$m=65536,t=3,p=4$c2FsdA==$aGFzaA==",
			expectedError: "hash algorithm switching is not implemented",
		},
		{
			name:          "UnsupportedVersionTooLow",
			hash:          "$argon2id$v=18$m=65536,t=3,p=4$c2FsdA==$aGFzaA==",
			expectedError: "unsupported hash algorithm version",
		},
		{
			name:          "InvalidParamsFormat",
			hash:          "$argon2id$v=19$m=65536,t=3$c2FsdA==$aGFzaA==",
			expectedError: "failed to scan hash algorithm params",
		},
		{
			name:          "InvalidBase64Salt",
			hash:          "$argon2id$v=19$m=65536,t=3,p=4$invalid-salt-$aGFzaA==",
			expectedError: "illegal base64 data",
		},
		{
			name:          "InvalidBase64Hash",
			hash:          "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA==$invalid-hash-",
			expectedError: "illegal base64 data",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			match, err := Check(password, tc.hash)

			if err == nil {
				t.Fatalf("Expected an error containing '%s', but got nil", tc.expectedError)
			}
			if !strings.Contains(err.Error(), tc.expectedError) {
				t.Errorf("Expected error message to contain '%s', but got '%s'", tc.expectedError, err.Error())
			}
			if match {
				t.Error("Expected match to be false when an error occurs, but got true")
			}
		})
	}
}

// TestHashPepperError tests that the Hash function fails correctly when the
// PEPPER environment variable is not set or is invalid.
func TestHashPepperError(t *testing.T) {
	// Backup and defer restore of the original pepper.
	originalPepper, isSet := os.LookupEnv("PEPPER")
	defer func() {
		if isSet {
			os.Setenv("PEPPER", originalPepper)
		} else {
			os.Unsetenv("PEPPER")
		}
	}()

	// 1. Test with PEPPER unset.
	os.Unsetenv("PEPPER")
	_, err := Hash("any-password")
	if err == nil {
		t.Fatal("Hash() did not return an error when PEPPER was not set")
	}
	expectedError := "pepper env is not valid"
	if err.Error() != expectedError {
		t.Errorf("Expected error message '%s', but got '%s'", expectedError, err.Error())
	}

	// 2. Test with PEPPER having an invalid length.
	os.Setenv("PEPPER", "a-short-and-invalid-pepper")
	_, err = Hash("any-password")
	if err == nil {
		t.Fatal("Hash() did not return an error when PEPPER has the wrong length")
	}
	if err.Error() != expectedError {
		t.Errorf("Expected error message '%s', but got '%s'", expectedError, err.Error())
	}
}
