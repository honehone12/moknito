package sys

import (
	"context"
	"moknito/ent/enttest"
	"moknito/hash"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ UserSys = &EntSys{}

func TestSystem_CreateUser(t *testing.T) {
	// Arrange
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	defer client.Close()

	system := &EntSys{ent: client}
	ctx := context.Background()

	name := "testuser"
	email := "test@example.com"
	password := "password123"

	// Act
	user, err := system.CreateUser(ctx, name, email, password)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, user)

	assert.Equal(t, name, user.Name)
	assert.Equal(t, email, user.Email)
	assert.NotEmpty(t, user.Pwhash)

	// Verify the password hash
	// Use the hash.Check function to verify the stored hash against the original password.
	ok, err := hash.Check(password, user.Pwhash)
	require.NoError(t, err)
	assert.True(t, ok, "hashed password should match the original password")

	// Verify the user exists in the database
	dbUser, err := client.User.Get(ctx, user.ID)
	require.NoError(t, err)
	require.NotNil(t, dbUser)
	assert.Equal(t, user.Name, dbUser.Name)
	assert.Equal(t, user.Email, dbUser.Email)
	assert.Equal(t, user.Pwhash, dbUser.Pwhash) // Ensure the hash stored is the same
}
