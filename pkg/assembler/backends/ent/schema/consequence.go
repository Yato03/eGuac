package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// Consequence holds the schema definition for the Consequence entity.
type Consequence struct {
	ent.Schema
}

// Fields of the Consequence.
func (Consequence) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(getUUIDv7).
			Unique().
			Immutable(),
		field.String("notes").Optional().Nillable(),
		field.String("likelihood").Optional().Nillable(),
	}
}

// Edges of the Consequence.
func (Consequence) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("cwe", CWE.Type).Ref("consequence"),
		edge.To("consequence_scope", Consequence_Scope.Type),
		edge.To("consequence_impact", Consequence_Impact.Type),
	}
}
