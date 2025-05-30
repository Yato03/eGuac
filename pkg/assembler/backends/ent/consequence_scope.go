// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/consequence_scope"
)

// Consequence_Scope is the model entity for the Consequence_Scope schema.
type Consequence_Scope struct {
	config `json:"-"`
	// ID of the ent.
	ID uuid.UUID `json:"id,omitempty"`
	// Scope holds the value of the "scope" field.
	Scope string `json:"scope,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the Consequence_ScopeQuery when eager-loading is set.
	Edges        Consequence_ScopeEdges `json:"edges"`
	selectValues sql.SelectValues
}

// Consequence_ScopeEdges holds the relations/edges for other nodes in the graph.
type Consequence_ScopeEdges struct {
	// Consequence holds the value of the consequence edge.
	Consequence []*Consequence `json:"consequence,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [1]bool
	// totalCount holds the count of the edges above.
	totalCount [1]map[string]int

	namedConsequence map[string][]*Consequence
}

// ConsequenceOrErr returns the Consequence value or an error if the edge
// was not loaded in eager-loading.
func (e Consequence_ScopeEdges) ConsequenceOrErr() ([]*Consequence, error) {
	if e.loadedTypes[0] {
		return e.Consequence, nil
	}
	return nil, &NotLoadedError{edge: "consequence"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*Consequence_Scope) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case consequence_scope.FieldScope:
			values[i] = new(sql.NullString)
		case consequence_scope.FieldID:
			values[i] = new(uuid.UUID)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the Consequence_Scope fields.
func (cs *Consequence_Scope) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case consequence_scope.FieldID:
			if value, ok := values[i].(*uuid.UUID); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value != nil {
				cs.ID = *value
			}
		case consequence_scope.FieldScope:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field scope", values[i])
			} else if value.Valid {
				cs.Scope = value.String
			}
		default:
			cs.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the Consequence_Scope.
// This includes values selected through modifiers, order, etc.
func (cs *Consequence_Scope) Value(name string) (ent.Value, error) {
	return cs.selectValues.Get(name)
}

// QueryConsequence queries the "consequence" edge of the Consequence_Scope entity.
func (cs *Consequence_Scope) QueryConsequence() *ConsequenceQuery {
	return NewConsequenceScopeClient(cs.config).QueryConsequence(cs)
}

// Update returns a builder for updating this Consequence_Scope.
// Note that you need to call Consequence_Scope.Unwrap() before calling this method if this Consequence_Scope
// was returned from a transaction, and the transaction was committed or rolled back.
func (cs *Consequence_Scope) Update() *ConsequenceScopeUpdateOne {
	return NewConsequenceScopeClient(cs.config).UpdateOne(cs)
}

// Unwrap unwraps the Consequence_Scope entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (cs *Consequence_Scope) Unwrap() *Consequence_Scope {
	_tx, ok := cs.config.driver.(*txDriver)
	if !ok {
		panic("ent: Consequence_Scope is not a transactional entity")
	}
	cs.config.driver = _tx.drv
	return cs
}

// String implements the fmt.Stringer.
func (cs *Consequence_Scope) String() string {
	var builder strings.Builder
	builder.WriteString("Consequence_Scope(")
	builder.WriteString(fmt.Sprintf("id=%v, ", cs.ID))
	builder.WriteString("scope=")
	builder.WriteString(cs.Scope)
	builder.WriteByte(')')
	return builder.String()
}

// NamedConsequence returns the Consequence named value or an error if the edge was not
// loaded in eager-loading with this name.
func (cs *Consequence_Scope) NamedConsequence(name string) ([]*Consequence, error) {
	if cs.Edges.namedConsequence == nil {
		return nil, &NotLoadedError{edge: name}
	}
	nodes, ok := cs.Edges.namedConsequence[name]
	if !ok {
		return nil, &NotLoadedError{edge: name}
	}
	return nodes, nil
}

func (cs *Consequence_Scope) appendNamedConsequence(name string, edges ...*Consequence) {
	if cs.Edges.namedConsequence == nil {
		cs.Edges.namedConsequence = make(map[string][]*Consequence)
	}
	if len(edges) == 0 {
		cs.Edges.namedConsequence[name] = []*Consequence{}
	} else {
		cs.Edges.namedConsequence[name] = append(cs.Edges.namedConsequence[name], edges...)
	}
}

// Consequence_Scopes is a parsable slice of Consequence_Scope.
type Consequence_Scopes []*Consequence_Scope
