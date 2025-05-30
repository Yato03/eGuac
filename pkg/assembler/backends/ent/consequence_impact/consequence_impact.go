// Code generated by ent, DO NOT EDIT.

package consequence_impact

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/google/uuid"
)

const (
	// Label holds the string label denoting the consequence_impact type in the database.
	Label = "consequence_impact"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldImpact holds the string denoting the impact field in the database.
	FieldImpact = "impact"
	// EdgeConsequence holds the string denoting the consequence edge name in mutations.
	EdgeConsequence = "consequence"
	// Table holds the table name of the consequence_impact in the database.
	Table = "consequence_impacts"
	// ConsequenceTable is the table that holds the consequence relation/edge. The primary key declared below.
	ConsequenceTable = "consequence_consequence_impact"
	// ConsequenceInverseTable is the table name for the Consequence entity.
	// It exists in this package in order to avoid circular dependency with the "consequence" package.
	ConsequenceInverseTable = "consequences"
)

// Columns holds all SQL columns for consequence_impact fields.
var Columns = []string{
	FieldID,
	FieldImpact,
}

var (
	// ConsequencePrimaryKey and ConsequenceColumn2 are the table columns denoting the
	// primary key for the consequence relation (M2M).
	ConsequencePrimaryKey = []string{"consequence_id", "consequence_impact_id"}
)

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	return false
}

var (
	// DefaultID holds the default value on creation for the "id" field.
	DefaultID func() uuid.UUID
)

// OrderOption defines the ordering options for the Consequence_Impact queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByImpact orders the results by the impact field.
func ByImpact(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldImpact, opts...).ToFunc()
}

// ByConsequenceCount orders the results by consequence count.
func ByConsequenceCount(opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborsCount(s, newConsequenceStep(), opts...)
	}
}

// ByConsequence orders the results by consequence terms.
func ByConsequence(term sql.OrderTerm, terms ...sql.OrderTerm) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newConsequenceStep(), append([]sql.OrderTerm{term}, terms...)...)
	}
}
func newConsequenceStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(ConsequenceInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2M, true, ConsequenceTable, ConsequencePrimaryKey...),
	)
}
