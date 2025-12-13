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

// Fields of the Session.
func (Authentication) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Immutable().
			Unique().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
		field.String("ip").
			Optional().
			MaxLen(256),
		field.String("user_agent").
			Optional().
			MaxLen(256),
		field.Time("logout_at").
			Optional().
			Nillable(),
	}
}

// Edges of the Session.
func (Authentication) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("sessions").
			Required().
			Unique(),
	}
}

func (Authentication) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Time{},
	}
}
