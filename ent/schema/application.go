package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Application holds the schema definition for the Application entity.
type Application struct {
	ent.Schema
}

func (Application) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Immutable().
			Unique().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
		field.String("name").
			NotEmpty().
			Unique(),
		field.String("domain").
			NotEmpty().
			Immutable().
			Unique(),
	}
}

func (Application) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owned", OwnedApp.Type).
			Ref("application").
			Immutable(),
	}
}

func (Application) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Time{},
	}
}
