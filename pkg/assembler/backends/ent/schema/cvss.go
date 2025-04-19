package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// CVSS holds the schema definition for the CVSS entity.
type CVSS struct {
	ent.Schema
}

// Fields of the CVSS.
func (CVSS) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(getUUIDv7).
			Unique().
			Immutable(),
		field.Float("vuln_impact"),
		field.String("version"),
		field.String("attack_vector"),
	}
}

// Edges of the CVSS.
func (CVSS) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("certify_vex", CertifyVex.Type).Ref("cvss"),
	}
}
