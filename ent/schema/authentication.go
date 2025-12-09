package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Authentication holds the schema definition for the Authentication entity.
type Authentication struct {
	ent.Schema
}

// Fields of the Authentication.
func (Authentication) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Immutable().
			Unique().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
		field.Bytes("code").
			Optional().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
		field.Bytes("challenge").
			Optional().
			SchemaType(map[string]string{dialect.MySQL: "binary(32)"}),
		field.Time("expire_at").
			Optional().
			Immutable(),
	}
}

// Edges of the Authentication.
func (Authentication) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).Ref("authentications").Unique(),
	}
}

func (Authentication) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Time{},
	}
}
