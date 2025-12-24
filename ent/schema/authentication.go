package schema

import (
	"moknito/binid"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Authentication holds the schema definition for the Authentication entity.
type Authentication struct {
	ent.Schema
}

func (Authentication) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", binid.BinId{}).
			Immutable().
			Unique().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
		field.String("ip").
			Optional().
			MaxLen(256),
		field.String("user_agent").
			Optional().
			MaxLen(256),
		field.Time("expire_at").
			Immutable(),
		field.Time("logout_at").
			Optional().
			Nillable(),
		field.UUID("user_id", binid.BinId{}).
			Immutable().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
	}
}

func (Authentication) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("authentications").
			Field("user_id").
			Required().
			Immutable().
			Unique(),
	}
}

func (Authentication) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Time{},
	}
}
