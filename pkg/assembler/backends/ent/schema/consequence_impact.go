package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// Consequence holds the schema definition for the Consequence entity.
type Consequence_Impact struct {
	ent.Schema
}

// Fields of the Consequence_Impact.
func (Consequence_Impact) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(getUUIDv7).
			Unique().
			Immutable(),
		field.String("impact"),
	}
}

// Edges of the Consequence_Impact.
func (Consequence_Impact) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("consequence", Consequence.Type).Ref("consequence_impact"),
	}
}
