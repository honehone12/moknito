package schema

import (
	"moknito/binid"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
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
		// this should be unique, yes
		// but i'm not sure we should return error as constraint
		field.Bytes("challenge").
			NotEmpty().
			Immutable().
			SchemaType(map[string]string{dialect.MySQL: "binary(32)"}),
		field.String("challenge_method").
			NotEmpty().
			Immutable().
			MaxLen(256),
		// this should be unique, yes
		// but i'm not sure we should return error as constraint
		field.Bytes("code").
			NotEmpty().
			Immutable().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
		field.Time("code_expire_at").
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

func (Authorization) Indexes() []ent.Index {
	return []ent.Index{
		// this should be unique, yes
		// but i'm not sure we should return error as constraint
		index.Fields("code"),
	}
}

func (Authorization) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Time{},
	}
}
