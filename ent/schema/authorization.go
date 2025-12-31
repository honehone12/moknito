package schema

import (
	"moknito/binid"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Authorization holds the schema definition for the Authorization entity.
type Authorization struct {
	ent.Schema
}

func (Authorization) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", binid.BinId{}).
			Immutable().
			Unique().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
		field.Enum("challenge_method").
			Values("S256", "plain").
			Immutable(),
		field.Time("code_consumed_at").
			Optional().
			Nillable(),
		field.Time("expire_at"),
		field.Time("refresh_expire_at"),
		field.UUID("application_id", binid.BinId{}).
			Immutable().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
		field.UUID("user_id", binid.BinId{}).
			Immutable().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
	}
}

func (Authorization) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("application", Application.Type).
			Field("application_id").
			Required().
			Immutable().
			Unique(),
		edge.From("user", User.Type).
			Ref("authorizations").
			Field("user_id").
			Required().
			Immutable().
			Unique(),
	}
}

func (Authorization) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Time{},
	}
}
