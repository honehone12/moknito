package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
)

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
	return []ent.Edge{
		edge.From("user", User.Type).Ref("sessions").Unique(),
	}
}

func (Session) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Time{},
	}
}
