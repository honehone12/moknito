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

func (Authorization) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Immutable().
			Unique().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
		// this should be unique, yes
		// but i'm not sure we should return error as constraint
		field.Bytes("code").
			NotEmpty().
			Immutable().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
		// this should be unique, yes
		// but i'm not sure we should return error as constraint
		field.Bytes("challenge").
			NotEmpty().
			Immutable().
			SchemaType(map[string]string{dialect.MySQL: "binary(32)"}),
		field.Time("expire_at").
			Immutable(),
		field.String("application_id").
			NotEmpty().
			Immutable().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
		field.String("user_id").
			NotEmpty().
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
