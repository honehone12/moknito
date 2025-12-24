package schema

import (
	"moknito/binid"

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
		field.UUID("id", binid.BinId{}).
			Immutable().
			Unique().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
		field.String("name").
			MaxLen(256).
			NotEmpty().
			Unique(),
		field.String("domain").
			MaxLen(256).
			NotEmpty().
			Immutable().
			Unique(),
		field.String("redirect").
			MaxLen(512).
			NotEmpty().
			Immutable().
			Unique(),
	}
}

func (Application) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("authorized", AuthorizedApp.Type).
			Ref("application").
			Immutable(),
		edge.From("logined", Authorization.Type).
			Ref("application").
			Immutable(),
	}
}

func (Application) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Time{},
	}
}
