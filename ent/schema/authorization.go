package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Authorization holds the schema definition for the Authorization entity.
type Authorization struct {
	ent.Schema
}

// Fields of the Authorization.
func (Authorization) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Immutable().
			Unique().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
		field.String("application").
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
func (Authorization) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("authorizations").
			Required().
			Unique(),
	}
}

func (Authorization) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Time{},
	}
}
