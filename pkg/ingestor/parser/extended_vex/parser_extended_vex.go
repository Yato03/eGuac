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

package extended_vex

import (
	"context"
	"fmt"

	json "github.com/json-iterator/go"
	"github.com/openvex/go-vex/pkg/vex"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/evex"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
)

var (
	justificationsMap = map[vex.Justification]generated.VexJustification{
		vex.ComponentNotPresent:                         generated.VexJustificationComponentNotPresent,
		vex.VulnerableCodeNotPresent:                    generated.VexJustificationVulnerableCodeNotPresent,
		vex.VulnerableCodeNotInExecutePath:              generated.VexJustificationVulnerableCodeNotInExecutePath,
		vex.VulnerableCodeCannotBeControlledByAdversary: generated.VexJustificationVulnerableCodeCannotBeControlledByAdversary,
		vex.InlineMitigationsAlreadyExist:               generated.VexJustificationInlineMitigationsAlreadyExist,
	}

	vexStatusMap = map[vex.Status]generated.VexStatus{
		vex.StatusNotAffected:        generated.VexStatusNotAffected,
		vex.StatusAffected:           generated.VexStatusAffected,
		vex.StatusFixed:              generated.VexStatusFixed,
		vex.StatusUnderInvestigation: generated.VexStatusUnderInvestigation,
	}
)

type ExtendedVEXParser struct {
	identifierStrings *common.IdentifierStrings
	vis               []assembler.VexIngest
	cvs               []assembler.CertifyVulnIngest
}

func NewExtendedVEXParser() common.DocumentParser {
	return &ExtendedVEXParser{
		identifierStrings: &common.IdentifierStrings{},
	}
}

// initializeExtendedVEXParser clears out all values for the next iteration
func (c *ExtendedVEXParser) initializeExtendedVEXParser() {
	c.vis = make([]assembler.VexIngest, 0)
	c.cvs = make([]assembler.CertifyVulnIngest, 0)
	c.identifierStrings = &common.IdentifierStrings{}
}

// Parse breaks out the document into the graph components
func (c *ExtendedVEXParser) Parse(ctx context.Context, doc *processor.Document) error {
	c.initializeExtendedVEXParser()
	var extendedVex *evex.ExtendedVEX
	err := json.Unmarshal(doc.Blob, &extendedVex)
	if err != nil {
		return fmt.Errorf("failed to unmarshal extendedVEX document: %w", err)
	}

	for _, s := range extendedVex.ExtendedStatements {
		vuln, err := helpers.CreateVulnInput(string(s.Vulnerability.Name))
		if err != nil {
			return fmt.Errorf("failed to create vulnerability input: %w", err)
		}

		vi, err := c.generateVexIngest(vuln, &s, string(s.Status), extendedVex)
		if err != nil {
			return fmt.Errorf("failed to generate vex ingest: %w", err)
		}

		for _, ingest := range vi {
			c.vis = append(c.vis, ingest)

			vulnData := generated.ScanMetadataInput{
				TimeScanned: *extendedVex.Timestamp,
			}
			cv := assembler.CertifyVulnIngest{
				Pkg:           ingest.Pkg,
				Vulnerability: vuln,
				VulnData:      &vulnData,
			}
			c.cvs = append(c.cvs, cv)
		}
	}

	return nil
}

// GetIdentities gets the identity node from the document if they exist
func (c *ExtendedVEXParser) GetIdentities(ctx context.Context) []common.TrustInformation {
	return nil
}

func (c *ExtendedVEXParser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	// filter our duplicate identifiers
	common.RemoveDuplicateIdentifiers(c.identifierStrings)
	return c.identifierStrings, nil
}

func (c *ExtendedVEXParser) generateVexIngest(vulnInput *generated.VulnerabilityInputSpec, vexStatement *evex.ExtendedStatement, status string, extendedVex *evex.ExtendedVEX) ([]assembler.VexIngest, error) {
	var vi []assembler.VexIngest

	for _, p := range extendedVex.ExtendedStatements {
		vd := generated.VexStatementInputSpec{}
		vd.KnownSince = *p.Timestamp
		vd.Origin = extendedVex.ID

		ingest := assembler.VexIngest{}

		if vexStatus, ok := vexStatusMap[vex.Status(status)]; ok {
			vd.Status = vexStatus
		} else {
			return nil, fmt.Errorf("invalid status for extendedVEX: %s", status)
		}

		vd.Statement = p.Vulnerability.Description

		if just, ok := justificationsMap[vexStatement.Justification]; ok {
			vd.VexJustification = just
		} else {
			vd.VexJustification = generated.VexJustificationNotProvided
		}

		for _, rc := range p.ReachableCode {
			vd.ReachableCode = append(vd.ReachableCode, &generated.ReachableCodeInputSpec{
				PathToFile: &rc.PathToFile,
			})
		}
		for _, exploit := range p.Exploits {
			vd.Exploits = append(vd.Exploits, &generated.ExploitsInputSpec{
				Description: &exploit.Description,
				Payload:     &exploit.Payload,
			})
		}
		vd.Description = &p.Vulnerability.Description

		vd.Cvss = &generated.CVSSInput{
			VulnImpact:   &p.Vulnerability.CVSS.VulnImpact,
			Version:      &p.Vulnerability.CVSS.Version,
			AttackString: &p.Vulnerability.CVSS.AttackVector,
		}

		for _, cwe := range p.Vulnerability.CWEs {
			vd.Cwe = append(vd.Cwe, &generated.CWEInput{
				ID:                   cwe.ID,
				Abstraction:          cwe.Description,
				Name:                 cwe.Name,
				PotentialMitigations: helpers.CreatePotentialMitigations(cwe),
				Consequences:         helpers.CreateConsequences(cwe),
				DemostrativeExamples: *helpers.ConvertToPointerSlice(cwe.DemostrativeExamples),
				DetectionMethods:     helpers.CreateDetectionMethods(cwe),
			})
		}

		ingest.VexData = &vd
		ingest.Vulnerability = vulnInput

		purl := helpers.AffectedComponentToPurl(string(p.AffectedComponentManager), string(p.AffectedComponent), string(p.AffectedComponentVersion))

		var err error
		if ingest.Pkg, err = helpers.PurlToPkg(purl); err != nil {
			return nil, err
		}

		c.identifierStrings.PurlStrings = append(c.identifierStrings.PurlStrings, purl)

		vi = append(vi, ingest)
	}

	return vi, nil
}

func (c *ExtendedVEXParser) GetPredicates(ctx context.Context) *assembler.IngestPredicates {
	return &assembler.IngestPredicates{
		Vex:         c.vis,
		CertifyVuln: c.cvs,
	}
}
