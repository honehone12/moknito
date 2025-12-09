package schema

import "entgo.io/ent"

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
	return nil
}

func (Authentication) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Time{},
	}
}
