package schema

import "entgo.io/ent"

// Session holds the schema definition for the Session entity.
type Session struct {
	ent.Schema
}

// Fields of the Session.
func (Session) Fields() []ent.Field {
	return nil
}

// Edges of the Session.
func (Session) Edges() []ent.Edge {
	return nil
}

func (Session) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Time{},
	}
}
