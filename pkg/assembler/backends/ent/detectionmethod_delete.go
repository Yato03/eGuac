// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/detectionmethod"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
)

// DetectionMethodDelete is the builder for deleting a DetectionMethod entity.
type DetectionMethodDelete struct {
	config
	hooks    []Hook
	mutation *DetectionMethodMutation
}

// Where appends a list predicates to the DetectionMethodDelete builder.
func (dmd *DetectionMethodDelete) Where(ps ...predicate.DetectionMethod) *DetectionMethodDelete {
	dmd.mutation.Where(ps...)
	return dmd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (dmd *DetectionMethodDelete) Exec(ctx context.Context) (int, error) {
	return withHooks(ctx, dmd.sqlExec, dmd.mutation, dmd.hooks)
}

// ExecX is like Exec, but panics if an error occurs.
func (dmd *DetectionMethodDelete) ExecX(ctx context.Context) int {
	n, err := dmd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (dmd *DetectionMethodDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := sqlgraph.NewDeleteSpec(detectionmethod.Table, sqlgraph.NewFieldSpec(detectionmethod.FieldID, field.TypeUUID))
	if ps := dmd.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, dmd.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	dmd.mutation.done = true
	return affected, err
}

// DetectionMethodDeleteOne is the builder for deleting a single DetectionMethod entity.
type DetectionMethodDeleteOne struct {
	dmd *DetectionMethodDelete
}

// Where appends a list predicates to the DetectionMethodDelete builder.
func (dmdo *DetectionMethodDeleteOne) Where(ps ...predicate.DetectionMethod) *DetectionMethodDeleteOne {
	dmdo.dmd.mutation.Where(ps...)
	return dmdo
}

// Exec executes the deletion query.
func (dmdo *DetectionMethodDeleteOne) Exec(ctx context.Context) error {
	n, err := dmdo.dmd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{detectionmethod.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (dmdo *DetectionMethodDeleteOne) ExecX(ctx context.Context) {
	if err := dmdo.Exec(ctx); err != nil {
		panic(err)
	}
}
