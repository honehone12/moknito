package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Application holds the schema definition for the Application entity.
type Application struct {
	ent.Schema
}

// Fields of the Authorization.
func (Application) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Immutable().
			Unique().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
		field.String("name").
			NotEmpty().
			Immutable(),
		field.String("domain").
			NotEmpty().
			Immutable(),
		field.String("client_id").
			NotEmpty().
			Immutable(),
	}
}

// Edges of the Authorization.
func (Application) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("authorizations").
			Required().
			Unique(),
	}
}

func (Application) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Time{},
	}
}
