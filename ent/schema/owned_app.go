package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Application holds the schema definition for the Application entity.
type OwnedApp struct {
	ent.Schema
}

func (OwnedApp) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Immutable().
			Unique().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
		field.String("name").
			NotEmpty(),
		field.String("domain").
			NotEmpty().
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

func (OwnedApp) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("owned_apps").
			Field("user_id").
			Required().
			Immutable().
			Unique(),
		edge.To("application", Application.Type).
			Field("application_id").
			Required().
			Immutable().
			Unique(),
	}
}

func (OwnedApp) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Time{},
	}
}
