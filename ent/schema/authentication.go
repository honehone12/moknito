package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
)

// Authentication holds the schema definition for the Authentication entity.
type Authentication struct {
	ent.Schema
}

// Fields of the Authentication.
func (Authentication) Fields() []ent.Field {
	return nil
}

// Edges of the Authentication.
func (Authentication) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).Ref("authentications").Unique(),
	}
}

func (Authentication) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Time{},
	}
}
