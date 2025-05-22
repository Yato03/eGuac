package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// DemonstrativeExample holds the schema definition for the DemonstrativeExample entity.
type DemonstrativeExample struct {
	ent.Schema
}

// Fields of the DemonstrativeExample.
func (DemonstrativeExample) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(getUUIDv7).
			Unique().
			Immutable(),
		field.String("description").Optional().Nillable(),
	}
}

// Edges of the DemonstrativeExample.
func (DemonstrativeExample) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("cwe", CWE.Type).Ref("demonstrative_example"),
	}
}
