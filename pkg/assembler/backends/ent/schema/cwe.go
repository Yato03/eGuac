package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// CWE holds the schema definition for the CWE entity.
type CWE struct {
	ent.Schema
}

// Fields of the CWE.
func (CWE) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(getUUIDv7).
			Unique().
			Immutable(),
		field.String("vex_id"),
		field.String("name"),
		field.String("description"),
		field.String("background_detail").Optional().Nillable(),
	}
}

// Edges of the CWE.
func (CWE) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("certify_vex", CertifyVex.Type).Ref("cwe"),
		edge.To("consequence", Consequence.Type),
		edge.To("demonstrative_example", DemonstrativeExample.Type),
		edge.To("detection_method", DetectionMethod.Type),
		edge.To("potential_mitigation", PotentialMitigation.Type),
	}
}
