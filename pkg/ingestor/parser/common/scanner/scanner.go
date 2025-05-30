//
// Copyright 2024 The GUAC Authors.
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

package scanner

import (
	"context"
	"fmt"
	"net/http"
	"time"

	deps_dev_client "github.com/guacsec/guac/internal/client/depsdevclient"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	cd_certifier "github.com/guacsec/guac/pkg/certifier/clearlydefined"
	eol_certifier "github.com/guacsec/guac/pkg/certifier/eol"
	osv_certifier "github.com/guacsec/guac/pkg/certifier/osv"
	"github.com/guacsec/guac/pkg/ingestor/parser/clearlydefined"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/ingestor/parser/eol"
	"github.com/guacsec/guac/pkg/ingestor/parser/vuln"
	"github.com/guacsec/guac/pkg/version"
)

// PurlsVulnScan takes a slice of purls and bulk queries OSV (skipping purls that start with "pkg:guac").
// Once the query returns, an attestation is generated and passed to the vulnerability parser for ingestion
func PurlsVulnScan(ctx context.Context, purls []string) ([]assembler.VulnEqualIngest, []assembler.CertifyVulnIngest, error) {
	// use the existing vulnerability parser to parse and obtain vuln Equal and certifyVuln values
	vulnParser := vuln.NewVulnCertificationParser()
	var vulnEquals []assembler.VulnEqualIngest
	var certifyVulns []assembler.CertifyVulnIngest

	if osvProcessorDocs, err := osv_certifier.EvaluateOSVResponse(ctx, &http.Client{
		Transport: version.UATransport,
	}, purls, nil, false); err != nil {
		return nil, nil, fmt.Errorf("failed get response from OSV with error: %w", err)
	} else {
		for _, doc := range osvProcessorDocs {
			err := vulnParser.Parse(ctx, doc)
			if err != nil {
				return nil, nil, fmt.Errorf("vulnerability parser failed with error: %w", err)
			}
			preds := vulnParser.GetPredicates(ctx)
			common.AddMetadata(preds, nil, doc.SourceInformation)
			certifyVulns = append(certifyVulns, preds.CertifyVuln...)
			vulnEquals = append(vulnEquals, preds.VulnEqual...)
		}
	}
	return vulnEquals, certifyVulns, nil
}

// PurlsLicenseScan takes a slice of purls and queries clearly defined (skipping purls that start with "pkg:guac").
// Once the query returns, an attestation is generated and passed to the clearly defined parser for ingestion
func PurlsLicenseScan(ctx context.Context, purls []string) ([]assembler.CertifyLegalIngest, []assembler.HasSourceAtIngest, error) {
	// default to using a client with the UA transport
	return purlsLicenseScanWithClient(ctx, &http.Client{Transport: version.UATransport}, purls)
}

// purlsLicenseScanWithClient is a helper function that allows for the injection of a client for testing purposes
func purlsLicenseScanWithClient(
	ctx context.Context, client *http.Client, purls []string,
) ([]assembler.CertifyLegalIngest, []assembler.HasSourceAtIngest, error) {
	// use the existing clearly defined parser to parse and obtain certifyLegal
	cdParser := clearlydefined.NewLegalCertificationParser()
	var certLegalIngest []assembler.CertifyLegalIngest
	var hasSourceAtIngest []assembler.HasSourceAtIngest

	// the limit for the batch size that is allowed for clearly defined otherwise you receive a 400 or 414
	if len(purls) > 500 {
		i := 0
		var batchPurls []string
		for _, purl := range purls {
			if i < 499 {
				batchPurls = append(batchPurls, purl)
				i++
			} else {
				batchPurls = append(batchPurls, purl)
				batchedCL, batchedHSA, err := runQueryOnBatchedPurls(ctx, client, cdParser, batchPurls)
				if err != nil {
					return nil, nil, fmt.Errorf("runQueryOnBatchedPurls failed with error: %w", err)
				}
				certLegalIngest = append(certLegalIngest, batchedCL...)
				hasSourceAtIngest = append(hasSourceAtIngest, batchedHSA...)
				batchPurls = make([]string, 0)
				i = 0
			}
		}
		if len(batchPurls) > 0 {
			batchedCL, batchedHSA, err := runQueryOnBatchedPurls(ctx, client, cdParser, batchPurls)
			if err != nil {
				return nil, nil, fmt.Errorf("runQueryOnBatchedPurls failed with error: %w", err)
			}
			certLegalIngest = append(certLegalIngest, batchedCL...)
			hasSourceAtIngest = append(hasSourceAtIngest, batchedHSA...)
		}
	} else {
		batchedCL, batchedHSA, err := runQueryOnBatchedPurls(ctx, client, cdParser, purls)
		if err != nil {
			return nil, nil, fmt.Errorf("runQueryOnBatchedPurls failed with error: %w", err)
		}
		certLegalIngest = append(certLegalIngest, batchedCL...)
		hasSourceAtIngest = append(hasSourceAtIngest, batchedHSA...)
	}

	return certLegalIngest, hasSourceAtIngest, nil
}

// PurlDepsDevScan scans the purls and returns for metadata linked to the repository
// and returns the list of scorecards and sources associations it finds from Deps.dev
// This generally takes about 300ms - 600ms. With tests including 1-30 PURLs.
func PurlsDepsDevScan(ctx context.Context, purls []string) ([]assembler.CertifyScorecardIngest, []assembler.HasSourceAtIngest, error) {
	certifyScorecards := []assembler.CertifyScorecardIngest{}
	hasSourceAts := []assembler.HasSourceAtIngest{}

	ddc, err := deps_dev_client.NewDepsClient(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to initialize deps.dev client: %w", err)

	}

	ddc.RetrieveVersionsAndProjects(ctx, purls)
	components, err := ddc.GetMetadata(ctx, purls)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get metadata for purls in deps.dev: %w", err)
	}

	for _, c := range components {
		hasSourceAt := createDepsDevHasSourceAtIngest(c.CurrentPackage, c.Source, c.UpdateTime.UTC())
		scorecard := createDepsDevScorecardIngest(c.Source, c.Scorecard)
		if hasSourceAt != nil {
			hasSourceAts = append(hasSourceAts, *hasSourceAt)
		}
		if scorecard != nil {
			certifyScorecards = append(certifyScorecards, *scorecard)
		}
	}
	return certifyScorecards, hasSourceAts, nil
}

func createDepsDevHasSourceAtIngest(pkg *generated.PkgInputSpec, src *generated.SourceInputSpec, knownSince time.Time) *assembler.HasSourceAtIngest {
	if pkg != nil && src != nil {
		return &assembler.HasSourceAtIngest{
			Pkg: pkg,
			PkgMatchFlag: generated.MatchFlags{
				Pkg: generated.PkgMatchTypeAllVersions,
			},
			Src: src,
			HasSourceAt: &generated.HasSourceAtInputSpec{
				KnownSince:    knownSince,
				Justification: "collected via deps.dev",
				Collector:     "ingest_depsdev_scanner",
				Origin:        "deps.dev",
			},
		}
	}
	return nil
}

func createDepsDevScorecardIngest(src *generated.SourceInputSpec, scorecard *generated.ScorecardInputSpec) *assembler.CertifyScorecardIngest {
	if src != nil && scorecard != nil {
		scorecard.Origin = "deps.dev"
		scorecard.Collector = "ingest_depsdev_scanner"

		return &assembler.CertifyScorecardIngest{
			Source:    src,
			Scorecard: scorecard,
		}
	}
	return nil
}

// runQueryOnBatchedPurls runs EvaluateClearlyDefinedDefinition from the clearly defined
// certifier to evaluate the batched purls for license information
func runQueryOnBatchedPurls(ctx context.Context, client *http.Client, cdParser common.DocumentParser, batchPurls []string) ([]assembler.CertifyLegalIngest, []assembler.HasSourceAtIngest, error) {
	var certLegalIngest []assembler.CertifyLegalIngest
	var hasSourceAtIngest []assembler.HasSourceAtIngest

	if cdProcessorDocs, err := cd_certifier.EvaluateClearlyDefinedDefinition(ctx, client, batchPurls, nil, false); err != nil {
		return nil, nil, fmt.Errorf("failed get definition from clearly defined with error: %w", err)
	} else {
		for _, doc := range cdProcessorDocs {
			err := cdParser.Parse(ctx, doc)
			if err != nil {
				return nil, nil, fmt.Errorf("vulnerability parser failed with error: %w", err)
			}
			preds := cdParser.GetPredicates(ctx)
			common.AddMetadata(preds, nil, doc.SourceInformation)
			certLegalIngest = append(certLegalIngest, preds.CertifyLegal...)
			hasSourceAtIngest = append(hasSourceAtIngest, preds.HasSourceAt...)
		}
	}
	return certLegalIngest, hasSourceAtIngest, nil
}

func PurlsEOLScan(ctx context.Context, purls []string) ([]assembler.HasMetadataIngest, error) {
	// use the existing EOL parser to parse and obtain EOL metadata
	eolParser := eol.NewEOLCertificationParser()
	var eolIngest []assembler.HasMetadataIngest

	if eolProcessorDocs, err := eol_certifier.EvaluateEOLResponse(ctx, &http.Client{
		Transport: version.UATransport,
	}, purls, nil); err != nil {
		return nil, fmt.Errorf("failed to get response from endoflife.date with error: %w", err)
	} else {
		for _, doc := range eolProcessorDocs {
			err := eolParser.Parse(ctx, doc)
			if err != nil {
				return nil, fmt.Errorf("EOL parser failed with error: %w", err)
			}
			preds := eolParser.GetPredicates(ctx)
			common.AddMetadata(preds, nil, doc.SourceInformation)
			eolIngest = append(eolIngest, preds.HasMetadata...)
		}
	}
	return eolIngest, nil
}
