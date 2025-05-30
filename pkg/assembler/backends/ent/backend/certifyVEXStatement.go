//
// Copyright 2023 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package backend

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"entgo.io/contrib/entgql"
	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyvex"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilityid"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func certifyVEXGlobalID(id string) string {
	return toGlobalID(certifyvex.Table, id)
}

func bulkCertifyVEXGlobalID(ids []string) []string {
	return toGlobalIDs(certifyvex.Table, ids)
}

func certifyVexConflictColumns() []string {
	return []string{
		certifyvex.FieldKnownSince,
		certifyvex.FieldStatus,
		certifyvex.FieldJustification,
		certifyvex.FieldOrigin,
		certifyvex.FieldCollector,
		certifyvex.FieldDocumentRef,
		certifyvex.FieldVulnerabilityID,
	}
}

func (b *EntBackend) IngestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.IDorVulnerabilityInput, vexStatement model.VexStatementInputSpec) (string, error) {
	funcName := "IngestVEXStatement"

	recordID, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		tx := ent.TxFromContext(ctx)
		conflictColumns := certifyVexConflictColumns()

		var conflictWhere *sql.Predicate

		if subject.Package != nil {
			conflictColumns = append(conflictColumns, certifyvex.FieldPackageID)
			conflictWhere = sql.And(
				sql.NotNull(certifyvex.FieldPackageID),
				sql.IsNull(certifyvex.FieldArtifactID),
			)
		} else if subject.Artifact != nil {
			conflictColumns = append(conflictColumns, certifyvex.FieldArtifactID)
			conflictWhere = sql.And(
				sql.IsNull(certifyvex.FieldPackageID),
				sql.NotNull(certifyvex.FieldArtifactID),
			)
		} else {
			return nil, Errorf("%v :: %s", funcName, "subject must be either a package or artifact")
		}

		insert, err := generateVexCreate(ctx, tx, subject.Package, subject.Artifact, &vulnerability, &vexStatement)
		if err != nil {
			return nil, gqlerror.Errorf("generateVexCreate :: %s", err)
		}

		if id, err := insert.
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			Ignore().
			ID(ctx); err != nil {

			return nil, errors.Wrap(err, "upsert certify vex statement node")

		} else {
			return ptrfrom.String(id.String()), nil
		}
	})

	if txErr != nil {
		return "", txErr
	}

	return certifyVEXGlobalID(*recordID), nil
}

func (b *EntBackend) IngestVEXStatements(ctx context.Context, subjects model.PackageOrArtifactInputs, vulnerabilities []*model.IDorVulnerabilityInput, vexStatements []*model.VexStatementInputSpec) ([]string, error) {
	funcName := "IngestVEXStatements"
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkVEX(ctx, client, subjects, vulnerabilities, vexStatements)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if txErr != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, txErr)
	}

	return bulkCertifyVEXGlobalID(*ids), nil
}

func generateVexCreate(ctx context.Context, tx *ent.Tx, pkg *model.IDorPkgInput, art *model.IDorArtifactInput, vuln *model.IDorVulnerabilityInput, vexStatement *model.VexStatementInputSpec) (*ent.CertifyVexCreate, error) {

	certifyVexCreate := tx.CertifyVex.Create()

	// manage vulnerability
	if vuln == nil {
		return nil, fmt.Errorf("vulnerability must be specified for vex ingestion")
	}

	var vulnID uuid.UUID
	if vuln.VulnerabilityNodeID != nil {
		var err error
		vulnGlobalID := fromGlobalID(*vuln.VulnerabilityNodeID)
		vulnID, err = uuid.Parse(vulnGlobalID.id)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from VulnerabilityNodeID failed with error: %w", err)
		}
	} else {
		foundVulnID, err := tx.VulnerabilityID.Query().
			Where(
				vulnerabilityid.VulnerabilityIDEqualFold(vuln.VulnerabilityInput.VulnerabilityID),
				vulnerabilityid.TypeEqualFold(vuln.VulnerabilityInput.Type),
			).
			OnlyID(ctx)
		if err != nil {
			return nil, Errorf("%v ::  %s", "generateVexCreate", err)
		}
		vulnID = foundVulnID
	}
	certifyVexCreate.SetVulnerabilityID(vulnID)

	// manage package or artifact
	if pkg != nil {
		var pkgVersionID uuid.UUID
		if pkg.PackageVersionID != nil {
			var err error
			pkgVersionGlobalID := fromGlobalID(*pkg.PackageVersionID)
			pkgVersionID, err = uuid.Parse(pkgVersionGlobalID.id)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from packageVersionID failed with error: %w", err)
			}
		} else {
			pv, err := getPkgVersion(ctx, tx.Client(), *pkg.PackageInput)
			if err != nil {
				return nil, fmt.Errorf("getPkgVersion :: %w", err)
			}
			pkgVersionID = pv.ID
		}
		certifyVexCreate.SetPackageID(pkgVersionID)

	} else if art != nil {
		var artID uuid.UUID
		if art.ArtifactID != nil {
			var err error
			artGlobalID := fromGlobalID(*art.ArtifactID)
			artID, err = uuid.Parse(artGlobalID.id)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
			}
		} else {
			foundArt, err := tx.Artifact.Query().Where(artifactQueryInputPredicates(*art.ArtifactInput)).Only(ctx)
			if err != nil {
				return nil, err
			}
			artID = foundArt.ID
		}
		certifyVexCreate.SetArtifactID(artID)
	} else {
		return nil, Errorf("%v :: %s", "generateVexCreate", "subject must be either a package or artifact")
	}

	certifyVexCreate.
		SetKnownSince(vexStatement.KnownSince.UTC()).
		SetStatus(vexStatement.Status.String()).
		SetStatement(vexStatement.Statement).
		SetStatusNotes(vexStatement.StatusNotes).
		SetJustification(vexStatement.VexJustification.String()).
		SetOrigin(vexStatement.Origin).
		SetCollector(vexStatement.Collector).
		SetDocumentRef(vexStatement.DocumentRef)

	if vexStatement.Description != nil {
		certifyVexCreate.SetDescription(*vexStatement.Description)
	}

	// Create and link CVSS if provided
	if vexStatement.Cvss != nil {
		cvss := tx.CVSS.Create()
		if vexStatement.Cvss.VulnImpact != nil {
			cvss.SetVulnImpact(*vexStatement.Cvss.VulnImpact)
		}
		if vexStatement.Cvss.Version != nil {
			cvss.SetVersion(*vexStatement.Cvss.Version)
		}
		if vexStatement.Cvss.AttackString != nil {
			cvss.SetAttackVector(*vexStatement.Cvss.AttackString)
		}
		cvssEntity, err := cvss.Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create CVSS: %w", err)
		}

		certifyVexCreate.SetCvss(cvssEntity)
	}

	// Create and link CWE if provided
	if vexStatement.Cwe != nil {
		for _, cwe := range vexStatement.Cwe {
			cwe_input := tx.CWE.Create()
			cwe_input.SetVexID(cwe.ID)
			cwe_input.SetName(cwe.Name)
			cwe_input.SetDescription(cwe.Abstraction)

			if cwe.BackgroundDetail != nil {
				cwe_input.SetBackgroundDetail(*cwe.BackgroundDetail)
			}

			// Create and link potential mitigations if provided
			if cwe.PotentialMitigations != nil {
				for _, mitigation := range cwe.PotentialMitigations {
					mitigation_input := tx.PotentialMitigation.Create()
					mitigation_input.SetPhase(*mitigation.Phase)
					mitigation_input.SetDescription(*mitigation.Description)
					mitigation_input.SetEffectiveness(*mitigation.Effectiveness)
					mitigation_input.SetEffectivenessNotes(*mitigation.EffectivenessNotes)

					mitigation_entity, err := mitigation_input.Save(ctx)
					if err != nil {
						return nil, fmt.Errorf("failed to create potential mitigation: %w", err)
					}

					cwe_input.AddPotentialMitigation(mitigation_entity)
				}
			}

			// Create and link detection methods if provided
			if cwe.DetectionMethods != nil {
				for _, detection := range cwe.DetectionMethods {
					detection_input := tx.DetectionMethod.Create()
					detection_input.SetDetectionID(*detection.ID)
					detection_input.SetDescription(*detection.Description)
					detection_input.SetEffectiveness(*detection.Effectiveness)
					detection_input.SetMethod(*detection.Method)
					detection_entity, err := detection_input.Save(ctx)

					if err != nil {
						return nil, fmt.Errorf("failed to create detection method: %w", err)
					}

					cwe_input.AddDetectionMethod(detection_entity)
				}
			}

			// Create and link Demonstrative examples if provided
			if cwe.DemonstrativeExamples != nil {
				for _, example := range cwe.DemonstrativeExamples {
					example_input := tx.DemonstrativeExample.Create()
					example_input.SetDescription(*example)
					example_entity, err := example_input.Save(ctx)

					if err != nil {
						return nil, fmt.Errorf("failed to create demonstrative example: %w", err)
					}

					cwe_input.AddDemonstrativeExample(example_entity)
				}
			}

			// Create and link Consequences if provided
			if cwe.Consequences != nil {
				for _, consequence := range cwe.Consequences {
					consequence_input := tx.Consequence.Create()
					consequence_input.SetNotes(*consequence.Notes)
					consequence_input.SetLikelihood(*consequence.Likelihood)

					// Create and link Scope if provided

					if consequence.Scope != nil {
						for _, scope := range consequence.Scope {
							scope_input := tx.Consequence_Scope.Create()
							scope_input.SetScope(*scope)
							scope_entity, err := scope_input.Save(ctx)

							if err != nil {
								return nil, fmt.Errorf("failed to create consequence scope: %w", err)
							}

							consequence_input.AddConsequenceScope(scope_entity)
						}
					}

					// Create and link Impact if provided
					if consequence.Impact != nil {
						for _, impact := range consequence.Impact {
							impact_input := tx.Consequence_Impact.Create()
							impact_input.SetImpact(*impact)
							impact_entity, err := impact_input.Save(ctx)

							if err != nil {
								return nil, fmt.Errorf("failed to create consequence impact: %w", err)
							}

							consequence_input.AddConsequenceImpact(impact_entity)
						}
					}

					consequence_entity, err := consequence_input.Save(ctx)

					if err != nil {
						return nil, fmt.Errorf("failed to create consequence: %w", err)
					}

					cwe_input.AddConsequence(consequence_entity)
				}
			}

			cweEntity, err := cwe_input.Save(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to create CWE: %w", err)
			}

			certifyVexCreate.AddCwe(cweEntity)
		}
	}

	// Create and link Exploit if provided
	if vexStatement.Exploits != nil {
		for _, exploit := range vexStatement.Exploits {
			exploit_input := tx.Exploit.Create()
			exploit_input.SetExploitID(*exploit.ID)
			exploit_input.SetDescription(*exploit.Description)
			exploit_input.SetPayload(*exploit.Payload)
			exploit_entity, err := exploit_input.Save(ctx)

			if err != nil {
				return nil, fmt.Errorf("failed to create exploit: %w", err)
			}

			certifyVexCreate.AddExploit(exploit_entity)
		}
	}

	// Create and link ReachableCode if provided
	if vexStatement.ReachableCode != nil {
		for _, reachableCode := range vexStatement.ReachableCode {
			reachableCode_input := tx.ReachableCode.Create()
			reachableCode_input.SetPathToFile(*reachableCode.PathToFile)

			// Create and link UsedArtifacts if provided
			if reachableCode.UsedArtifacts != nil {
				for _, artifact := range reachableCode.UsedArtifacts {
					artifact_input := tx.ReachableCodeArtifact.Create()
					artifact_input.SetArtifactName(*artifact.Name)

					// Make used lines [1,2,3] : int[] convert to 1,2,3 string
					var usedLines []string
					for _, line := range artifact.UsedInLines {
						usedLines = append(usedLines, strconv.Itoa(*line))
					}
					artifact_input.SetUsedInLines(strings.Join(usedLines, ","))

					artifact_entity, err := artifact_input.Save(ctx)

					if err != nil {
						return nil, fmt.Errorf("failed to create used artifact: %w", err)
					}

					reachableCode_input.AddReachableCodeArtifact(artifact_entity)
				}
			}
			reachableCode_entity, err := reachableCode_input.Save(ctx)

			if err != nil {
				return nil, fmt.Errorf("failed to create reachable code: %w", err)
			}

			certifyVexCreate.AddReachableCode(reachableCode_entity)
		}
	}

	if vexStatement.Priority != nil {
		certifyVexCreate.SetPriority(*vexStatement.Priority)
	}

	return certifyVexCreate, nil
}

func upsertBulkVEX(ctx context.Context, tx *ent.Tx, subjects model.PackageOrArtifactInputs, vulnerabilities []*model.IDorVulnerabilityInput, vexStatements []*model.VexStatementInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	conflictColumns := certifyVexConflictColumns()

	var conflictWhere *sql.Predicate

	if len(subjects.Packages) > 0 {
		conflictColumns = append(conflictColumns, certifyvex.FieldPackageID)
		conflictWhere = sql.And(
			sql.NotNull(certifyvex.FieldPackageID),
			sql.IsNull(certifyvex.FieldArtifactID),
		)
	} else if len(subjects.Artifacts) > 0 {
		conflictColumns = append(conflictColumns, certifyvex.FieldArtifactID)
		conflictWhere = sql.And(
			sql.IsNull(certifyvex.FieldPackageID),
			sql.NotNull(certifyvex.FieldArtifactID),
		)
	}

	batches := chunk(vexStatements, MaxBatchSize)

	index := 0
	for _, vexs := range batches {
		creates := make([]*ent.CertifyVexCreate, len(vexs))
		for i, vex := range vexs {
			vex := vex
			var err error
			if len(subjects.Packages) > 0 {
				creates[i], err = generateVexCreate(ctx, tx, subjects.Packages[index], nil, vulnerabilities[index], vex)
				if err != nil {
					return nil, gqlerror.Errorf("generateVexCreate :: %s", err)
				}
			} else if len(subjects.Artifacts) > 0 {
				creates[i], err = generateVexCreate(ctx, tx, nil, subjects.Artifacts[index], vulnerabilities[index], vex)
				if err != nil {
					return nil, gqlerror.Errorf("generateVexCreate :: %s", err)
				}
			}
			index++
		}

		err := tx.CertifyVex.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			UpdateNewValues().
			Exec(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "bulk upsert certifyVex node")
		}
	}

	return &ids, nil
}

func (b *EntBackend) CertifyVEXStatementList(ctx context.Context, spec model.CertifyVEXStatementSpec, after *string, first *int) (*model.VEXConnection, error) {
	var afterCursor *entgql.Cursor[uuid.UUID]

	if after != nil {
		globalID := fromGlobalID(*after)
		if globalID.nodeType != certifyvex.Table {
			return nil, fmt.Errorf("after cursor is not type certifyVEX but type: %s", globalID.nodeType)
		}
		afterUUID, err := uuid.Parse(globalID.id)
		if err != nil {
			return nil, fmt.Errorf("failed to parse global ID with error: %w", err)
		}
		afterCursor = &ent.Cursor{ID: afterUUID}
	} else {
		afterCursor = nil
	}

	vexQuery := b.client.CertifyVex.Query().
		Where(certifyVexPredicate(spec))

	certVEXConn, err := getVEXObject(vexQuery).
		Paginate(ctx, afterCursor, first, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed CertifyVEXStatement query with error: %w", err)
	}

	// if not found return nil
	if certVEXConn == nil {
		return nil, nil
	}

	var edges []*model.VEXEdge
	for _, edge := range certVEXConn.Edges {
		edges = append(edges, &model.VEXEdge{
			Cursor: certifyVEXGlobalID(edge.Cursor.ID.String()),
			Node:   toModelCertifyVEXStatement(edge.Node),
		})
	}

	if certVEXConn.PageInfo.StartCursor != nil {
		return &model.VEXConnection{
			TotalCount: certVEXConn.TotalCount,
			PageInfo: &model.PageInfo{
				HasNextPage: certVEXConn.PageInfo.HasNextPage,
				StartCursor: ptrfrom.String(certifyVEXGlobalID(certVEXConn.PageInfo.StartCursor.ID.String())),
				EndCursor:   ptrfrom.String(certifyVEXGlobalID(certVEXConn.PageInfo.EndCursor.ID.String())),
			},
			Edges: edges,
		}, nil
	} else {
		// if not found return nil
		return nil, nil
	}
}

func (b *EntBackend) CertifyVEXStatement(ctx context.Context, spec *model.CertifyVEXStatementSpec) ([]*model.CertifyVEXStatement, error) {
	if spec == nil {
		spec = &model.CertifyVEXStatementSpec{}
	}

	vexQuery := b.client.CertifyVex.Query().
		Where(certifyVexPredicate(*spec))

	records, err := getVEXObject(vexQuery).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed CertifyVEXStatement query with error: %w", err)
	}

	return collect(records, toModelCertifyVEXStatement), nil
}

// getVEXObject is used to recreate the VEX object by eager loading the edges
func getVEXObject(q *ent.CertifyVexQuery) *ent.CertifyVexQuery {
	return q.
		WithVulnerability(func(q *ent.VulnerabilityIDQuery) {
		}).
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.WithName(func(q *ent.PackageNameQuery) {})
		}).
		WithArtifact().
		WithCvss().
		WithCwe(func(q *ent.CWEQuery) {
			q.WithDemonstrativeExample()
			q.WithDetectionMethod()
			q.WithPotentialMitigation()
			q.WithConsequence(func(q *ent.ConsequenceQuery) {
				q.WithConsequenceImpact()
				q.WithConsequenceScope()
			})
		}).
		WithExploit().
		WithReachableCode(func(q *ent.ReachableCodeQuery) {
			q.WithReachableCodeArtifact()
		})
}

func toModelCertifyVEXStatement(record *ent.CertifyVex) *model.CertifyVEXStatement {

	var subject model.PackageOrArtifact
	if record.Edges.Package != nil {
		subject = model.Package{
			ID:   record.Edges.Package.ID.String(),
			Type: record.Edges.Package.Edges.Name.Type,
		}
	} else if record.Edges.Artifact != nil {
		subject = model.Artifact{
			ID:        record.Edges.Artifact.ID.String(),
			Algorithm: record.Edges.Artifact.Algorithm,
			Digest:    record.Edges.Artifact.Digest,
		}
	}

	return &model.CertifyVEXStatement{
		ID:               certifyVEXGlobalID(record.ID.String()),
		Vulnerability:    toModelVulnerabilityFromVulnerabilityID(record.Edges.Vulnerability),
		KnownSince:       record.KnownSince,
		Subject:          subject,
		Status:           model.VexStatus(record.Status),
		Statement:        record.Statement,
		StatusNotes:      record.StatusNotes,
		VexJustification: model.VexJustification(record.Justification),
		Origin:           record.Origin,
		Collector:        record.Collector,
		DocumentRef:      record.DocumentRef,
		Description:      record.Description,
		Cvss:             toModelCvss(record.Edges.Cvss),
		Cwe:              toModelCwes(record.Edges.Cwe),
		Exploits:         toModelExploits(record.Edges.Exploit),
		ReachableCode:    toModelReachableCodes(record.Edges.ReachableCode),
		Priority:         record.Priority,
	}
}

func certifyVexPredicate(filter model.CertifyVEXStatementSpec) predicate.CertifyVex {
	predicates := []predicate.CertifyVex{
		optionalPredicate(filter.ID, IDEQ),
		optionalPredicate(filter.KnownSince, certifyvex.KnownSinceEQ),
		optionalPredicate(filter.Statement, certifyvex.StatementEQ),
		optionalPredicate(filter.StatusNotes, certifyvex.StatusNotesEQ),
		optionalPredicate(filter.Collector, certifyvex.CollectorEQ),
		optionalPredicate(filter.Origin, certifyvex.OriginEQ),
		optionalPredicate(filter.DocumentRef, certifyvex.DocumentRefEQ),
		optionalPredicate(filter.Description, certifyvex.DescriptionEQ),
	}
	if filter.Status != nil {
		status := filter.Status.String()
		predicates = append(predicates, optionalPredicate(&status, certifyvex.StatusEQ))
	}
	if filter.VexJustification != nil {
		justification := filter.VexJustification.String()
		predicates = append(predicates, optionalPredicate(&justification, certifyvex.JustificationEQ))
	}

	if filter.Subject != nil {
		if filter.Subject.Package != nil {
			if filter.Subject.Package.ID != nil {
				predicates = append(predicates, optionalPredicate(filter.Subject.Package.ID, packageIDEQ))
			} else {
				predicates = append(predicates,
					certifyvex.HasPackageWith(packageVersionQuery(filter.Subject.Package)))
			}
		} else if filter.Subject.Artifact != nil {
			if filter.Subject.Artifact.ID != nil {
				predicates = append(predicates,
					optionalPredicate(filter.Subject.Artifact.ID, artifactIDEQ))
			} else {
				predicates = append(predicates,
					certifyvex.HasArtifactWith(artifactQueryPredicates(filter.Subject.Artifact)))
			}
		}
	}

	if filter.Vulnerability != nil {
		if filter.Vulnerability.ID != nil {
			predicates = append(predicates, optionalPredicate(filter.Vulnerability.ID, vulnerabilityIDEQ))
		} else {
			if filter.Vulnerability.NoVuln != nil && *filter.Vulnerability.NoVuln {
				predicates = append(predicates, certifyvex.Not(certifyvex.HasVulnerability()))
			} else {
				predicates = append(predicates,
					certifyvex.HasVulnerabilityWith(
						vulnerabilityQueryPredicates(*filter.Vulnerability)...,
					),
				)
			}
		}
	}
	return certifyvex.And(predicates...)
}

func (b *EntBackend) certifyVexNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]model.Node, error) {
	var out []model.Node

	query := b.client.CertifyVex.Query().
		Where(certifyVexPredicate(model.CertifyVEXStatementSpec{ID: &nodeID}))

	if allowedEdges[model.EdgeCertifyVexStatementPackage] {
		query.
			WithPackage(withPackageVersionTree())
	}
	if allowedEdges[model.EdgeCertifyVexStatementArtifact] {
		query.
			WithArtifact()
	}
	if allowedEdges[model.EdgeCertifyVexStatementVulnerability] {
		query.
			WithVulnerability()
	}

	certVexs, err := query.All(ctx)
	if err != nil {
		return []model.Node{}, fmt.Errorf("failed to query for certifyVex with node ID: %s with error: %w", nodeID, err)
	}

	for _, foundVex := range certVexs {
		if foundVex.Edges.Package != nil {
			out = append(out, toModelPackage(backReferencePackageVersion(foundVex.Edges.Package)))
		}
		if foundVex.Edges.Artifact != nil {
			out = append(out, toModelArtifact(foundVex.Edges.Artifact))
		}
		if foundVex.Edges.Vulnerability != nil {
			out = append(out, toModelVulnerabilityFromVulnerabilityID(foundVex.Edges.Vulnerability))
		}
	}

	return out, nil
}
