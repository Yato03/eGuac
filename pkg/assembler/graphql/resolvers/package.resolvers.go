package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.60

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/graphql/generated"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/helpers"
)

// IngestPackage is the resolver for the ingestPackage field.
func (r *mutationResolver) IngestPackage(ctx context.Context, pkg model.IDorPkgInput) (*model.PackageIDs, error) {
	// Return the ids of the package which has been ingested

	return r.Backend.IngestPackage(ctx, pkg)
}

// IngestPackages is the resolver for the ingestPackages field.
func (r *mutationResolver) IngestPackages(ctx context.Context, pkgs []*model.IDorPkgInput) ([]*model.PackageIDs, error) {
	return r.Backend.IngestPackages(ctx, pkgs)
}

// Namespaces is the resolver for the namespaces field.
func (r *packageResolver) Namespaces(ctx context.Context, obj *model.Package) ([]*model.PackageNamespace, error) {
	return helpers.UpdatePurlForPackageNamespaces(obj)
}

// Packages is the resolver for the packages field.
func (r *queryResolver) Packages(ctx context.Context, pkgSpec model.PkgSpec) ([]*model.Package, error) {
	return r.Backend.Packages(ctx, &pkgSpec)
}

// PackagesList is the resolver for the packagesList field.
func (r *queryResolver) PackagesList(ctx context.Context, pkgSpec model.PkgSpec, after *string, first *int) (*model.PackageConnection, error) {
	return r.Backend.PackagesList(ctx, pkgSpec, after, first)
}

// Package returns generated.PackageResolver implementation.
func (r *Resolver) Package() generated.PackageResolver { return &packageResolver{r} }

type packageResolver struct{ *Resolver }
