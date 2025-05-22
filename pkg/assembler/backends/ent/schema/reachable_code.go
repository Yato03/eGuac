package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// ReachableCode holds the schema definition for the ReachableCode entity.
type ReachableCode struct {
	ent.Schema
}

// Fields of the ReachableCode.
func (ReachableCode) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(getUUIDv7).
			Unique().
			Immutable(),
		field.String("path_to_file").Optional().Nillable(),
	}
}

// Edges of the ReachableCode.
func (ReachableCode) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("certify_vex", CertifyVex.Type).Ref("reachable_code"),
		edge.To("reachable_code_artifact", ReachableCodeArtifact.Type),
	}
}
