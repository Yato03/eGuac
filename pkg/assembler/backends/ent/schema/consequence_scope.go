package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// Consequence holds the schema definition for the Consequence entity.
type Consequence_Scope struct {
	ent.Schema
}

// Fields of the Consequence_Scope.
func (Consequence_Scope) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(getUUIDv7).
			Unique().
			Immutable(),
		field.String("scope"),
	}
}

// Edges of the Consequence_Scope.
func (Consequence_Scope) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("consequence", Consequence.Type).Ref("consequence_scope"),
	}
}
