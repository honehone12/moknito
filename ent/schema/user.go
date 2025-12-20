package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// User holds the schema definition for the User entity.
type User struct {
	ent.Schema
}

// Fields of the User.
func (User) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Immutable().
			Unique().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
		field.String("name").
			NotEmpty().
			MaxLen(256),
		field.String("email").
			NotEmpty().
			MaxLen(256).
			Unique(),
		field.String("pwhash").
			NotEmpty().
			MaxLen(512),
	}
}

// Edges of the User.
func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("authentications", Authentication.Type).
			Immutable(),
		edge.To("authorizations", Authorization.Type).
			Immutable(),
		edge.To("authorized_apps", AuthorizedApp.Type).
			Immutable(),
	}
}

func (User) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("email").Unique(),
	}
}

func (User) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Time{},
	}
}
