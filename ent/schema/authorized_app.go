package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Application holds the schema definition for the Application entity.
type AuthorizedApp struct {
	ent.Schema
}

func (AuthorizedApp) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Immutable().
			Unique().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
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

func (AuthorizedApp) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("application", Application.Type).
			Field("application_id").
			Required().
			Immutable().
			Unique(),
		edge.From("user", User.Type).
			Ref("authorized_apps").
			Field("user_id").
			Required().
			Immutable().
			Unique(),
	}
}

func (AuthorizedApp) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Time{},
	}
}
