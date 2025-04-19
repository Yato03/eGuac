package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// Consequence holds the schema definition for the Consequence entity.
type ReachableCodeArtifact struct {
	ent.Schema
}

// Fields of the ReachableCodeArtifact.
func (ReachableCodeArtifact) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(getUUIDv7).
			Unique().
			Immutable(),
		field.String("artifact_name").Optional().Nillable(),
		field.String("used_in_lines").Optional().Nillable(),
	}
}

// Edges of the ReachableCodeArtifact.
func (ReachableCodeArtifact) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("reachable_code", ReachableCode.Type).Ref("reachable_code_artifact"),
	}
}
