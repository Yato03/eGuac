package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// DetectionMethod holds the schema definition for the DetectionMethod entity.
type DetectionMethod struct {
	ent.Schema
}

// Fields of the DetectionMethod.
func (DetectionMethod) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(getUUIDv7).
			Unique().
			Immutable(),
		field.String("detection_id").Optional().Nillable(),
		field.String("method").Optional().Nillable(),
		field.String("description").Optional().Nillable(),
		field.String("effectiveness").Optional().Nillable(),
	}
}

// Edges of the DetectionMethod.
func (DetectionMethod) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("cwe", CWE.Type).Ref("detection_method"),
	}
}
