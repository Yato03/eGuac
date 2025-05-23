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

package keyvalue

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/guacsec/guac/internal/testing/ptrfrom"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/kv"
)

// Internal data: link between a package or an artifact with its corresponding
// vulnerability VEX statement
type vexLink struct {
	ThisID          string
	PackageID       string
	ArtifactID      string
	VulnerabilityID string
	KnownSince      time.Time
	Status          model.VexStatus
	Statement       string
	StatusNotes     string
	Justification   model.VexJustification
	Origin          string
	Collector       string
	DocumentRef     string
	Description     string
	Exploits        []model.Exploits
	ReachableCode   []model.ReachableCode
	Cvss            model.CVSSInput
	Cwe             []model.CWEInput
	Priority        float64
}

func convertCweInputs(inputs []*model.CWEInput) []model.CWEInput {
	var result []model.CWEInput
	for _, input := range inputs {
		result = append(result, *input)
	}
	return result
}

func convertCweInputsToPointers(inputs []model.CWEInput) []*model.CWEInput {
	var result []*model.CWEInput
	for _, input := range inputs {
		inputCopy := input
		result = append(result, &inputCopy)
	}
	return result
}

func ConvertCwesToPointers(inputs []model.Cwe) []*model.Cwe {
	var result []*model.Cwe
	for _, input := range inputs {
		inputCopy := input
		result = append(result, &inputCopy)
	}
	return result
}

func (n *vexLink) ID() string { return n.ThisID }

func (n *vexLink) Key() string {
	return hashKey(strings.Join([]string{
		n.PackageID,
		n.ArtifactID,
		n.VulnerabilityID,
		timeKey(n.KnownSince),
		string(n.Status),
		n.Statement,
		n.StatusNotes,
		string(n.Justification),
		n.Origin,
		n.Collector,
		n.DocumentRef,
		n.Description,
		fmt.Sprintf("%f", n.Priority),
	}, ":"))
}

func (n *vexLink) Neighbors(allowedEdges edgeMap) []string {
	out := make([]string, 0, 2)
	if n.PackageID != "" && allowedEdges[model.EdgeCertifyVexStatementPackage] {
		out = append(out, n.PackageID)
	}
	if n.ArtifactID != "" && allowedEdges[model.EdgeCertifyVexStatementArtifact] {
		out = append(out, n.ArtifactID)
	}
	if allowedEdges[model.EdgeCertifyVexStatementVulnerability] {
		out = append(out, n.VulnerabilityID)
	}
	return out
}

func (n *vexLink) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.buildCertifyVEXStatement(ctx, n, nil, true)
}

// Ingest CertifyVex

func (c *demoClient) IngestVEXStatements(ctx context.Context, subjects model.PackageOrArtifactInputs, vulnerabilities []*model.IDorVulnerabilityInput, vexStatements []*model.VexStatementInputSpec) ([]string, error) {
	var modelVexStatementIDs []string

	for i := range vexStatements {
		var certVex string
		var err error
		if len(subjects.Packages) > 0 {
			subject := model.PackageOrArtifactInput{Package: subjects.Packages[i]}
			certVex, err = c.IngestVEXStatement(ctx, subject, *vulnerabilities[i], *vexStatements[i])
			if err != nil {
				return nil, gqlerror.Errorf("IngestVEXStatement failed with err: %v", err)
			}
		} else {
			subject := model.PackageOrArtifactInput{Artifact: subjects.Artifacts[i]}
			certVex, err = c.IngestVEXStatement(ctx, subject, *vulnerabilities[i], *vexStatements[i])
			if err != nil {
				return nil, gqlerror.Errorf("IngestVEXStatement failed with err: %v", err)
			}
		}
		modelVexStatementIDs = append(modelVexStatementIDs, certVex)
	}
	return modelVexStatementIDs, nil
}

func (c *demoClient) IngestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.IDorVulnerabilityInput, vexStatement model.VexStatementInputSpec) (string, error) {
	return c.ingestVEXStatement(ctx, subject, vulnerability, vexStatement, true)
}

func (c *demoClient) ingestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.IDorVulnerabilityInput, vexStatement model.VexStatementInputSpec, readOnly bool) (string, error) {
	funcName := "IngestVEXStatement"

	in := &vexLink{
		KnownSince:    vexStatement.KnownSince.UTC(),
		Status:        vexStatement.Status,
		Statement:     vexStatement.Statement,
		StatusNotes:   vexStatement.StatusNotes,
		Justification: vexStatement.VexJustification,
		Origin:        vexStatement.Origin,
		Collector:     vexStatement.Collector,
		DocumentRef:   vexStatement.DocumentRef,
		Description:   "",
	}

	if vexStatement.Description != nil {
		in.Statement = *vexStatement.Description
	}

	if vexStatement.Cvss != nil {
		in.Cvss = *vexStatement.Cvss
	}

	if vexStatement.Cwe != nil {
		in.Cwe = convertCweInputs(vexStatement.Cwe)
	}

	if vexStatement.Exploits != nil {
		in.Exploits = ConvertExploitsInputs(vexStatement.Exploits)
	}

	if vexStatement.ReachableCode != nil {
		in.ReachableCode = ConvertReachableCodeInputs(vexStatement.ReachableCode)
	}

	if vexStatement.Priority != nil {
		in.Priority = *vexStatement.Priority
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	var foundPkgVersionNode *pkgVersion
	var foundArtStruct *artStruct
	if subject.Package != nil {
		var err error
		foundPkgVersionNode, err = c.returnFoundPkgVersion(ctx, subject.Package)
		if err != nil {
			return "", gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		in.PackageID = foundPkgVersionNode.ID()
	} else {
		var err error
		foundArtStruct, err = c.returnFoundArtifact(ctx, subject.Artifact)
		if err != nil {
			return "", gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		in.ArtifactID = foundArtStruct.ID()
	}

	foundVulnNode, err := c.returnFoundVulnerability(ctx, &vulnerability)
	if err != nil {
		return "", gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	in.VulnerabilityID = foundVulnNode.ID()

	out, err := byKeykv[*vexLink](ctx, cVEXCol, in.Key(), c)
	if err == nil {
		return out.ThisID, nil
	}
	if !errors.Is(err, kv.NotFoundError) {
		return "", err
	}

	if readOnly {
		c.m.RUnlock()
		v, err := c.ingestVEXStatement(ctx, subject, vulnerability, vexStatement, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return v, err
	}

	in.ThisID = c.getNextID()
	if err := c.addToIndex(ctx, cVEXCol, in); err != nil {
		return "", err
	}
	// set the backlinks
	if foundPkgVersionNode != nil {
		if err := foundPkgVersionNode.setVexLinks(ctx, in.ThisID, c); err != nil {
			return "", err
		}
	} else {
		if err := foundArtStruct.setVexLinks(ctx, in.ThisID, c); err != nil {
			return "", err
		}
	}
	if err := foundVulnNode.setVexLinks(ctx, in.ThisID, c); err != nil {
		return "", err
	}
	if err := setkv(ctx, cVEXCol, in, c); err != nil {
		return "", err
	}

	return in.ThisID, nil
}

// Query CertifyVex

func (c *demoClient) CertifyVEXStatementList(ctx context.Context, certifyVEXStatementSpec model.CertifyVEXStatementSpec, after *string, first *int) (*model.VEXConnection, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	funcName := "CertifyVEXStatement"

	if certifyVEXStatementSpec.ID != nil {
		link, err := byIDkv[*vexLink](ctx, *certifyVEXStatementSpec.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		foundCertifyVex, err := c.buildCertifyVEXStatement(ctx, link, &certifyVEXStatementSpec, true)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}

		return &model.VEXConnection{
			TotalCount: 1,
			PageInfo: &model.PageInfo{
				HasNextPage: false,
				StartCursor: ptrfrom.String(foundCertifyVex.ID),
				EndCursor:   ptrfrom.String(foundCertifyVex.ID),
			},
			Edges: []*model.VEXEdge{
				{
					Cursor: foundCertifyVex.ID,
					Node:   foundCertifyVex,
				},
			},
		}, nil
	}

	edges := make([]*model.VEXEdge, 0)
	hasNextPage := false
	numNodes := 0
	totalCount := 0
	addToCount := 0

	var search []string
	foundOne := false

	if certifyVEXStatementSpec.Subject != nil && certifyVEXStatementSpec.Subject.Artifact != nil {
		exactArtifact, err := c.artifactExact(ctx, certifyVEXStatementSpec.Subject.Artifact)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactArtifact != nil {
			search = append(search, exactArtifact.VexLinks...)
			foundOne = true
		}
	}
	if !foundOne && certifyVEXStatementSpec.Subject != nil && certifyVEXStatementSpec.Subject.Package != nil {
		pkgs, err := c.findPackageVersion(ctx, certifyVEXStatementSpec.Subject.Package)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		foundOne = len(pkgs) > 0
		for _, pkg := range pkgs {
			search = append(search, pkg.VexLinks...)
		}
	}
	if !foundOne && certifyVEXStatementSpec.Vulnerability != nil {
		exactVuln, err := c.exactVulnerability(ctx, certifyVEXStatementSpec.Vulnerability)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactVuln != nil {
			search = append(search, exactVuln.VexLinks...)
			foundOne = true
		}
	}

	if foundOne {
		for _, id := range search {
			link, err := byIDkv[*vexLink](ctx, id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			vex, err := c.vexIfMatch(ctx, &certifyVEXStatementSpec, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			if vex == nil {
				continue
			}

			if (after != nil && vex.ID > *after) || after == nil {
				addToCount += 1

				if first != nil {
					if numNodes < *first {
						edges = append(edges, &model.VEXEdge{
							Cursor: vex.ID,
							Node:   vex,
						})
						numNodes++
					} else if numNodes == *first {
						hasNextPage = true
					}
				} else {
					edges = append(edges, &model.VEXEdge{
						Cursor: vex.ID,
						Node:   vex,
					})
				}
			}
		}
	} else {
		currentPage := false

		// If no cursor present start from the top
		if after == nil {
			currentPage = true
		}

		var done bool
		scn := c.kv.Keys(cVEXCol)

		for !done {
			var keys []string
			var err error
			keys, done, err = scn.Scan(ctx)
			if err != nil {
				return nil, err
			}

			sort.Strings(keys)
			totalCount = len(keys)

			for i, key := range keys {
				link, err := byKeykv[*vexLink](ctx, cVEXCol, key, c)
				if err != nil {
					return nil, err
				}
				vex, err := c.vexIfMatch(ctx, &certifyVEXStatementSpec, link)
				if err != nil {
					return nil, gqlerror.Errorf("%vex :: %vex", funcName, err)
				}

				if vex == nil {
					continue
				}

				if after != nil && !currentPage {
					if vex.ID == *after {
						totalCount = len(keys) - (i + 1)
						currentPage = true
					}
					continue
				}

				if first != nil {
					if numNodes < *first {
						edges = append(edges, &model.VEXEdge{
							Cursor: vex.ID,
							Node:   vex,
						})
						numNodes++
					} else if numNodes == *first {
						hasNextPage = true
					}
				} else {
					edges = append(edges, &model.VEXEdge{
						Cursor: vex.ID,
						Node:   vex,
					})
				}
			}
		}
	}

	if len(edges) != 0 {
		return &model.VEXConnection{
			TotalCount: totalCount + addToCount,
			PageInfo: &model.PageInfo{
				HasNextPage: hasNextPage,
				StartCursor: ptrfrom.String(edges[0].Node.ID),
				EndCursor:   ptrfrom.String(edges[max(numNodes-1, 0)].Node.ID),
			},
			Edges: edges,
		}, nil
	}
	return nil, nil
}

func (c *demoClient) CertifyVEXStatement(ctx context.Context, filter *model.CertifyVEXStatementSpec) ([]*model.CertifyVEXStatement, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	funcName := "CertifyVEXStatement"

	if filter != nil && filter.ID != nil {
		link, err := byIDkv[*vexLink](ctx, *filter.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		foundCertifyVex, err := c.buildCertifyVEXStatement(ctx, link, filter, true)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.CertifyVEXStatement{foundCertifyVex}, nil
	}

	var search []string
	foundOne := false

	if filter != nil && filter.Subject != nil && filter.Subject.Artifact != nil {
		exactArtifact, err := c.artifactExact(ctx, filter.Subject.Artifact)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactArtifact != nil {
			search = append(search, exactArtifact.VexLinks...)
			foundOne = true
		}
	}
	if !foundOne && filter != nil && filter.Subject != nil && filter.Subject.Package != nil {
		pkgs, err := c.findPackageVersion(ctx, filter.Subject.Package)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		foundOne = len(pkgs) > 0
		for _, pkg := range pkgs {
			search = append(search, pkg.VexLinks...)
		}
	}
	if !foundOne && filter != nil && filter.Vulnerability != nil {
		exactVuln, err := c.exactVulnerability(ctx, filter.Vulnerability)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactVuln != nil {
			search = append(search, exactVuln.VexLinks...)
			foundOne = true
		}
	}

	var out []*model.CertifyVEXStatement
	if foundOne {
		for _, id := range search {
			link, err := byIDkv[*vexLink](ctx, id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			v, err := c.vexIfMatch(ctx, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}

			if v == nil {
				continue
			}

			out = append(out, v)
		}
	} else {
		var done bool
		scn := c.kv.Keys(cVEXCol)
		for !done {
			var keys []string
			var err error
			keys, done, err = scn.Scan(ctx)
			if err != nil {
				return nil, err
			}
			for _, key := range keys {
				link, err := byKeykv[*vexLink](ctx, cVEXCol, key, c)
				if err != nil {
					return nil, err
				}
				v, err := c.vexIfMatch(ctx, filter, link)
				if err != nil {
					return nil, gqlerror.Errorf("%v :: %v", funcName, err)
				}

				if v == nil {
					continue
				}

				out = append(out, v)
			}
		}
	}
	return out, nil
}

func (c *demoClient) vexIfMatch(ctx context.Context, filter *model.CertifyVEXStatementSpec, link *vexLink) (
	*model.CertifyVEXStatement, error) {

	if filter != nil && filter.KnownSince != nil && !filter.KnownSince.Equal(link.KnownSince) {
		return nil, nil
	}
	if filter != nil && filter.VexJustification != nil && *filter.VexJustification != link.Justification {
		return nil, nil
	}
	if filter != nil && filter.Status != nil && *filter.Status != link.Status {
		return nil, nil
	}
	if filter != nil && noMatch(filter.Statement, link.Statement) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.StatusNotes, link.StatusNotes) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.Collector, link.Collector) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.Origin, link.Origin) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.DocumentRef, link.DocumentRef) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.Description, link.Description) {
		return nil, nil
	}
	if filter != nil && filter.Cvss != nil {
		if filter.Cvss.AttackString != nil && *filter.Cvss.AttackString != *link.Cvss.AttackString {
			return nil, nil
		}
		if filter.Cvss.VulnImpact != nil && *filter.Cvss.VulnImpact != *link.Cvss.VulnImpact {
			return nil, nil
		}
		if filter.Cvss.Version != nil && *filter.Cvss.Version != *link.Cvss.Version {
			return nil, nil
		}
	}

	foundCertifyVex, err := c.buildCertifyVEXStatement(ctx, link, filter, false)
	if err != nil {
		return nil, err
	}
	if foundCertifyVex == nil {
		return nil, nil
	}
	return foundCertifyVex, nil
}

func (c *demoClient) buildCertifyVEXStatement(ctx context.Context, link *vexLink, filter *model.CertifyVEXStatementSpec, ingestOrIDProvided bool) (*model.CertifyVEXStatement, error) {
	var p *model.Package
	var a *model.Artifact
	var vuln *model.Vulnerability
	var err error
	if filter != nil && filter.Subject != nil {
		if filter.Subject.Package != nil && link.PackageID != "" {
			p, err = c.buildPackageResponse(ctx, link.PackageID, filter.Subject.Package)
			if err != nil {
				return nil, err
			}
		}
		if filter.Subject.Artifact != nil && link.ArtifactID != "" {
			a, err = c.buildArtifactResponse(ctx, link.ArtifactID, filter.Subject.Artifact)
			if err != nil {
				return nil, err
			}
		}
	} else {
		if link.PackageID != "" {
			p, err = c.buildPackageResponse(ctx, link.PackageID, nil)
			if err != nil {
				return nil, err
			}
		}
		if link.ArtifactID != "" {
			a, err = c.buildArtifactResponse(ctx, link.ArtifactID, nil)
			if err != nil {
				return nil, err
			}
		}
	}

	if filter != nil && filter.Vulnerability != nil {
		if filter.Vulnerability != nil && link.VulnerabilityID != "" {
			vuln, err = c.buildVulnResponse(ctx, link.VulnerabilityID, filter.Vulnerability)
			if err != nil {
				return nil, err
			}
		}
	} else {
		if link.VulnerabilityID != "" {
			vuln, err = c.buildVulnResponse(ctx, link.VulnerabilityID, nil)
			if err != nil {
				return nil, err
			}
		}
	}

	var subj model.PackageOrArtifact
	if link.PackageID != "" {
		if p == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve package via packageID")
		} else if p == nil && !ingestOrIDProvided {
			return nil, nil
		}
		subj = p
	}
	if link.ArtifactID != "" {
		if a == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve artifact via artifactID")
		} else if a == nil && !ingestOrIDProvided {
			return nil, nil
		}
		subj = a
	}

	if link.VulnerabilityID != "" {
		if vuln == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve vuln via vulnID")
		} else if vuln == nil && !ingestOrIDProvided {
			return nil, nil
		}
	}

	return &model.CertifyVEXStatement{
		ID:               link.ThisID,
		Subject:          subj,
		Status:           link.Status,
		VexJustification: link.Justification,
		Statement:        link.Statement,
		StatusNotes:      link.StatusNotes,
		KnownSince:       link.KnownSince,
		Origin:           link.Origin,
		Collector:        link.Collector,
		DocumentRef:      link.DocumentRef,
		Description:      &link.Description,
		Exploits:         ConvertExploitToPointers(link.Exploits),
		ReachableCode:    ConvertReachableCodeToPointers(link.ReachableCode),
		Cvss:             (*model.Cvss)(&link.Cvss),
		Cwe:              convertCwesInputToCwes(convertCweInputsToPointers(link.Cwe)),
		Priority:         &link.Priority,
	}, nil
}

func ConvertReachableCodeInputs(reachableCodeInputSpec []*model.ReachableCodeInputSpec) []model.ReachableCode {
	var result []model.ReachableCode
	for _, input := range reachableCodeInputSpec {
		result = append(result, model.ReachableCode{
			PathToFile:    input.PathToFile,
			UsedArtifacts: convertUsedArtifactInputs(input.UsedArtifacts),
		})
	}
	return result
}

func ConvertReachableCodeToPointers(inputs []model.ReachableCode) []*model.ReachableCode {
	var result []*model.ReachableCode
	for _, input := range inputs {
		inputCopy := input
		result = append(result, &inputCopy)
	}
	return result
}

func convertUsedArtifactInputs(usedArtifactInputSpec []*model.UsedArtifactInputSpec) []*model.UsedArtifact {
	var result []*model.UsedArtifact
	for _, input := range usedArtifactInputSpec {
		artifact := model.UsedArtifact{
			Name:        input.Name,
			UsedInLines: input.UsedInLines,
		}
		result = append(result, &artifact)
	}
	return result
}

func ConvertExploitsInputs(exploitsInputSpec []*model.ExploitsInputSpec) []model.Exploits {
	var result []model.Exploits
	for _, input := range exploitsInputSpec {
		result = append(result, model.Exploits{
			ID:          input.ID,
			Description: input.Description,
			Payload:     input.Payload,
		})
	}
	return result
}

func ConvertExploitToPointers(inputs []model.Exploits) []*model.Exploits {
	var result []*model.Exploits
	for _, input := range inputs {
		inputCopy := input
		result = append(result, &inputCopy)
	}
	return result
}

func convertCwesInputToCwes(input []*model.CWEInput) []*model.Cwe {
	var out []*model.Cwe
	for _, cwe := range input {
		cweValue := convertCweInputToCwe(*cwe)
		out = append(out, &cweValue)
	}
	return out
}

func convertCweInputToCwe(input model.CWEInput) model.Cwe {
	var potentialMitigations []*model.PotentialMitigations

	if input.PotentialMitigations != nil {
		for _, mitigation := range input.PotentialMitigations {
			p := model.PotentialMitigations{
				Phase:              mitigation.Phase,
				Description:        mitigation.Description,
				Effectiveness:      mitigation.Effectiveness,
				EffectivenessNotes: mitigation.EffectivenessNotes,
			}
			potentialMitigations = append(potentialMitigations, &p)
		}
	}

	var consequences []*model.Consequences

	if input.Consequences != nil {
		for _, consequence := range input.Consequences {
			c := model.Consequences{
				Scope:      consequence.Scope,
				Impact:     consequence.Impact,
				Notes:      consequence.Notes,
				Likelihood: consequence.Likelihood,
			}
			consequences = append(consequences, &c)
		}
	}

	var detectionMethods []*model.DetectionMethods

	if input.DetectionMethods != nil {
		for _, detectionMethod := range input.DetectionMethods {
			d := model.DetectionMethods{
				ID:            detectionMethod.ID,
				Method:        detectionMethod.Method,
				Description:   detectionMethod.Description,
				Effectiveness: detectionMethod.Effectiveness,
			}
			detectionMethods = append(detectionMethods, &d)
		}
	}

	return model.Cwe{
		ID:                    input.ID,
		Abstraction:           input.Abstraction,
		Name:                  input.Name,
		BackgroundDetail:      input.BackgroundDetail,
		PotentialMitigations:  potentialMitigations,
		Consequences:          consequences,
		DemonstrativeExamples: input.DemonstrativeExamples,
		DetectionMethods:      detectionMethods,
	}
}

func ConvertCwesInputSpecToCwes(input []*model.CWEInputSpec) []*model.Cwe {
	var out []*model.Cwe
	for _, cwe := range input {
		cweValue := convertCweInputSpecToCwe(*cwe)
		out = append(out, &cweValue)
	}
	return out
}

func convertCweInputSpecToCwe(input model.CWEInputSpec) model.Cwe {
	var potentialMitigations []*model.PotentialMitigations

	if input.PotentialMitigations != nil {
		for _, mitigation := range input.PotentialMitigations {
			p := model.PotentialMitigations{
				Phase:              mitigation.Phase,
				Description:        mitigation.Description,
				Effectiveness:      mitigation.Effectiveness,
				EffectivenessNotes: mitigation.EffectivenessNotes,
			}
			potentialMitigations = append(potentialMitigations, &p)
		}
	}

	var consequences []*model.Consequences

	if input.Consequences != nil {
		for _, consequence := range input.Consequences {
			c := model.Consequences{
				Scope:      consequence.Scope,
				Impact:     consequence.Impact,
				Notes:      consequence.Notes,
				Likelihood: consequence.Likelihood,
			}
			consequences = append(consequences, &c)
		}
	}

	var detectionMethods []*model.DetectionMethods

	if input.DetectionMethods != nil {
		for _, detectionMethod := range input.DetectionMethods {
			d := model.DetectionMethods{
				ID:            detectionMethod.ID,
				Method:        detectionMethod.Method,
				Description:   detectionMethod.Description,
				Effectiveness: detectionMethod.Effectiveness,
			}
			detectionMethods = append(detectionMethods, &d)
		}
	}

	return model.Cwe{
		ID:                    *input.ID,
		Abstraction:           *input.Abstraction,
		Name:                  *input.Name,
		BackgroundDetail:      input.BackgroundDetail,
		PotentialMitigations:  potentialMitigations,
		Consequences:          consequences,
		DemonstrativeExamples: input.DemonstrativeExamples,
		DetectionMethods:      detectionMethods,
	}
}
