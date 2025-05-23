// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/cwe"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/demonstrativeexample"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
)

// DemonstrativeExampleUpdate is the builder for updating DemonstrativeExample entities.
type DemonstrativeExampleUpdate struct {
	config
	hooks    []Hook
	mutation *DemonstrativeExampleMutation
}

// Where appends a list predicates to the DemonstrativeExampleUpdate builder.
func (deu *DemonstrativeExampleUpdate) Where(ps ...predicate.DemonstrativeExample) *DemonstrativeExampleUpdate {
	deu.mutation.Where(ps...)
	return deu
}

// SetDescription sets the "description" field.
func (deu *DemonstrativeExampleUpdate) SetDescription(s string) *DemonstrativeExampleUpdate {
	deu.mutation.SetDescription(s)
	return deu
}

// SetNillableDescription sets the "description" field if the given value is not nil.
func (deu *DemonstrativeExampleUpdate) SetNillableDescription(s *string) *DemonstrativeExampleUpdate {
	if s != nil {
		deu.SetDescription(*s)
	}
	return deu
}

// ClearDescription clears the value of the "description" field.
func (deu *DemonstrativeExampleUpdate) ClearDescription() *DemonstrativeExampleUpdate {
	deu.mutation.ClearDescription()
	return deu
}

// AddCweIDs adds the "cwe" edge to the CWE entity by IDs.
func (deu *DemonstrativeExampleUpdate) AddCweIDs(ids ...uuid.UUID) *DemonstrativeExampleUpdate {
	deu.mutation.AddCweIDs(ids...)
	return deu
}

// AddCwe adds the "cwe" edges to the CWE entity.
func (deu *DemonstrativeExampleUpdate) AddCwe(c ...*CWE) *DemonstrativeExampleUpdate {
	ids := make([]uuid.UUID, len(c))
	for i := range c {
		ids[i] = c[i].ID
	}
	return deu.AddCweIDs(ids...)
}

// Mutation returns the DemonstrativeExampleMutation object of the builder.
func (deu *DemonstrativeExampleUpdate) Mutation() *DemonstrativeExampleMutation {
	return deu.mutation
}

// ClearCwe clears all "cwe" edges to the CWE entity.
func (deu *DemonstrativeExampleUpdate) ClearCwe() *DemonstrativeExampleUpdate {
	deu.mutation.ClearCwe()
	return deu
}

// RemoveCweIDs removes the "cwe" edge to CWE entities by IDs.
func (deu *DemonstrativeExampleUpdate) RemoveCweIDs(ids ...uuid.UUID) *DemonstrativeExampleUpdate {
	deu.mutation.RemoveCweIDs(ids...)
	return deu
}

// RemoveCwe removes "cwe" edges to CWE entities.
func (deu *DemonstrativeExampleUpdate) RemoveCwe(c ...*CWE) *DemonstrativeExampleUpdate {
	ids := make([]uuid.UUID, len(c))
	for i := range c {
		ids[i] = c[i].ID
	}
	return deu.RemoveCweIDs(ids...)
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (deu *DemonstrativeExampleUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, deu.sqlSave, deu.mutation, deu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (deu *DemonstrativeExampleUpdate) SaveX(ctx context.Context) int {
	affected, err := deu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (deu *DemonstrativeExampleUpdate) Exec(ctx context.Context) error {
	_, err := deu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (deu *DemonstrativeExampleUpdate) ExecX(ctx context.Context) {
	if err := deu.Exec(ctx); err != nil {
		panic(err)
	}
}

func (deu *DemonstrativeExampleUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := sqlgraph.NewUpdateSpec(demonstrativeexample.Table, demonstrativeexample.Columns, sqlgraph.NewFieldSpec(demonstrativeexample.FieldID, field.TypeUUID))
	if ps := deu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := deu.mutation.Description(); ok {
		_spec.SetField(demonstrativeexample.FieldDescription, field.TypeString, value)
	}
	if deu.mutation.DescriptionCleared() {
		_spec.ClearField(demonstrativeexample.FieldDescription, field.TypeString)
	}
	if deu.mutation.CweCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   demonstrativeexample.CweTable,
			Columns: demonstrativeexample.CwePrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(cwe.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := deu.mutation.RemovedCweIDs(); len(nodes) > 0 && !deu.mutation.CweCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   demonstrativeexample.CweTable,
			Columns: demonstrativeexample.CwePrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(cwe.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := deu.mutation.CweIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   demonstrativeexample.CweTable,
			Columns: demonstrativeexample.CwePrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(cwe.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, deu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{demonstrativeexample.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	deu.mutation.done = true
	return n, nil
}

// DemonstrativeExampleUpdateOne is the builder for updating a single DemonstrativeExample entity.
type DemonstrativeExampleUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *DemonstrativeExampleMutation
}

// SetDescription sets the "description" field.
func (deuo *DemonstrativeExampleUpdateOne) SetDescription(s string) *DemonstrativeExampleUpdateOne {
	deuo.mutation.SetDescription(s)
	return deuo
}

// SetNillableDescription sets the "description" field if the given value is not nil.
func (deuo *DemonstrativeExampleUpdateOne) SetNillableDescription(s *string) *DemonstrativeExampleUpdateOne {
	if s != nil {
		deuo.SetDescription(*s)
	}
	return deuo
}

// ClearDescription clears the value of the "description" field.
func (deuo *DemonstrativeExampleUpdateOne) ClearDescription() *DemonstrativeExampleUpdateOne {
	deuo.mutation.ClearDescription()
	return deuo
}

// AddCweIDs adds the "cwe" edge to the CWE entity by IDs.
func (deuo *DemonstrativeExampleUpdateOne) AddCweIDs(ids ...uuid.UUID) *DemonstrativeExampleUpdateOne {
	deuo.mutation.AddCweIDs(ids...)
	return deuo
}

// AddCwe adds the "cwe" edges to the CWE entity.
func (deuo *DemonstrativeExampleUpdateOne) AddCwe(c ...*CWE) *DemonstrativeExampleUpdateOne {
	ids := make([]uuid.UUID, len(c))
	for i := range c {
		ids[i] = c[i].ID
	}
	return deuo.AddCweIDs(ids...)
}

// Mutation returns the DemonstrativeExampleMutation object of the builder.
func (deuo *DemonstrativeExampleUpdateOne) Mutation() *DemonstrativeExampleMutation {
	return deuo.mutation
}

// ClearCwe clears all "cwe" edges to the CWE entity.
func (deuo *DemonstrativeExampleUpdateOne) ClearCwe() *DemonstrativeExampleUpdateOne {
	deuo.mutation.ClearCwe()
	return deuo
}

// RemoveCweIDs removes the "cwe" edge to CWE entities by IDs.
func (deuo *DemonstrativeExampleUpdateOne) RemoveCweIDs(ids ...uuid.UUID) *DemonstrativeExampleUpdateOne {
	deuo.mutation.RemoveCweIDs(ids...)
	return deuo
}

// RemoveCwe removes "cwe" edges to CWE entities.
func (deuo *DemonstrativeExampleUpdateOne) RemoveCwe(c ...*CWE) *DemonstrativeExampleUpdateOne {
	ids := make([]uuid.UUID, len(c))
	for i := range c {
		ids[i] = c[i].ID
	}
	return deuo.RemoveCweIDs(ids...)
}

// Where appends a list predicates to the DemonstrativeExampleUpdate builder.
func (deuo *DemonstrativeExampleUpdateOne) Where(ps ...predicate.DemonstrativeExample) *DemonstrativeExampleUpdateOne {
	deuo.mutation.Where(ps...)
	return deuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (deuo *DemonstrativeExampleUpdateOne) Select(field string, fields ...string) *DemonstrativeExampleUpdateOne {
	deuo.fields = append([]string{field}, fields...)
	return deuo
}

// Save executes the query and returns the updated DemonstrativeExample entity.
func (deuo *DemonstrativeExampleUpdateOne) Save(ctx context.Context) (*DemonstrativeExample, error) {
	return withHooks(ctx, deuo.sqlSave, deuo.mutation, deuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (deuo *DemonstrativeExampleUpdateOne) SaveX(ctx context.Context) *DemonstrativeExample {
	node, err := deuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (deuo *DemonstrativeExampleUpdateOne) Exec(ctx context.Context) error {
	_, err := deuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (deuo *DemonstrativeExampleUpdateOne) ExecX(ctx context.Context) {
	if err := deuo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (deuo *DemonstrativeExampleUpdateOne) sqlSave(ctx context.Context) (_node *DemonstrativeExample, err error) {
	_spec := sqlgraph.NewUpdateSpec(demonstrativeexample.Table, demonstrativeexample.Columns, sqlgraph.NewFieldSpec(demonstrativeexample.FieldID, field.TypeUUID))
	id, ok := deuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "DemonstrativeExample.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := deuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, demonstrativeexample.FieldID)
		for _, f := range fields {
			if !demonstrativeexample.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != demonstrativeexample.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := deuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := deuo.mutation.Description(); ok {
		_spec.SetField(demonstrativeexample.FieldDescription, field.TypeString, value)
	}
	if deuo.mutation.DescriptionCleared() {
		_spec.ClearField(demonstrativeexample.FieldDescription, field.TypeString)
	}
	if deuo.mutation.CweCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   demonstrativeexample.CweTable,
			Columns: demonstrativeexample.CwePrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(cwe.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := deuo.mutation.RemovedCweIDs(); len(nodes) > 0 && !deuo.mutation.CweCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   demonstrativeexample.CweTable,
			Columns: demonstrativeexample.CwePrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(cwe.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := deuo.mutation.CweIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   demonstrativeexample.CweTable,
			Columns: demonstrativeexample.CwePrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(cwe.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &DemonstrativeExample{config: deuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, deuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{demonstrativeexample.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	deuo.mutation.done = true
	return _node, nil
}
