package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Login holds the schema definition for the Login entity.
type Login struct {
	ent.Schema
}

// Fields of the Session.
func (Login) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Immutable().
			Unique().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
		field.Time("login_at").
			Optional(),
		field.String("ip").
			Optional().
			MaxLen(256),
		field.String("user_agent").
			Optional().
			MaxLen(256),
		field.String("application").
			MaxLen(256),
	}
}

// Edges of the Session.
func (Login) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("sessions").
			Required().
			Unique(),
	}
}

func (Login) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Time{},
	}
}
