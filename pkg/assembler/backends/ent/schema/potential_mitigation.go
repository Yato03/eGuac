package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// PotentialMitigation holds the schema definition for the PotentialMitigation entity.
type PotentialMitigation struct {
	ent.Schema
}

// Fields of the PotentialMitigation.
func (PotentialMitigation) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(getUUIDv7).
			Unique().
			Immutable(),
		field.String("phase").Optional().Nillable(),
		field.String("description").Optional().Nillable(),
		field.String("effectiveness").Optional().Nillable(),
		field.String("effectiveness_notes").Optional().Nillable(),
	}
}

// Edges of the PotentialMitigation.
func (PotentialMitigation) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("cwe", CWE.Type).Ref("potential_mitigation"),
	}
}
