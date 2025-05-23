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

package assembler

import (
	"context"
	"fmt"
	"testing"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

func TestIngestPredicates(t *testing.T) {
	ctx := context.Background()
	slsaStartTime, _ := time.Parse(time.RFC3339, "2020-08-19T08:38:00Z")
	tm, _ := time.Parse(time.RFC3339, "2022-11-21T17:45:50.52Z")
	topLevelPack, _ := helpers.PurlToPkg("pkg:guac/spdx/gcr.io/google-containers/alpine-latest")
	baselayoutPack, _ := helpers.PurlToPkg("pkg:alpine/alpine-baselayout@3.2.0-r22?arch=x86_64&upstream=alpine-baselayout&distro=alpine-3.16.2")
	baselayoutdataPack, _ := helpers.PurlToPkg("pkg:alpine/alpine-baselayout-data@3.2.0-r22?arch=x86_64&upstream=alpine-baselayout&distro=alpine-3.16.2")
	worldFilePack, _ := helpers.PurlToPkg(helpers.GuacFilePurl("sha256", "713e3907167dce202d7c16034831af3d670191382a3e9026e0ac0a4023013201", ptrfrom.String("/etc/apk/world")))
	worldFileArtifact := &generated.ArtifactInputSpec{
		Algorithm: "sha256",
		Digest:    "713e3907167dce202d7c16034831af3d670191382a3e9026e0ac0a4023013201",
	}
	k8sSource := &generated.SourceInputSpec{
		Type:      "git",
		Namespace: "github.com/kubernetes",
		Name:      "kubernetes",
		Commit:    ptrfrom.String("5835544ca568b757a8ecae5c153f317e5736700e"),
	}
	maven := &generated.PkgInputSpec{
		Type:      "maven",
		Namespace: ptrfrom.String("org.apache.logging.log4j"),
		Name:      "log4j-core",
		Version:   ptrfrom.String("2.8.1"),
		Subpath:   ptrfrom.String(""),
	}
	openSSLWithQualifier := &generated.PkgInputSpec{
		Type:       "conan",
		Namespace:  ptrfrom.String("openssl.org"),
		Name:       "openssl",
		Version:    ptrfrom.String("3.0.3"),
		Qualifiers: []generated.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
		Subpath:    ptrfrom.String(""),
	}
	openSSL := &generated.PkgInputSpec{
		Type:       "conan",
		Namespace:  ptrfrom.String("openssl.org"),
		Name:       "openssl2",
		Version:    ptrfrom.String("3.0.3"),
		Qualifiers: []generated.PackageQualifierInputSpec{},
		Subpath:    ptrfrom.String(""),
	}
	rootFilePack, _ := helpers.PurlToPkg(helpers.GuacFilePurl("sha256", "575d810a9fae5f2f0671c9b2c0ce973e46c7207fbe5cb8d1b0d1836a6a0470e3", ptrfrom.String("/etc/crontabs/root")))
	rootFileArtifact := &generated.ArtifactInputSpec{
		Algorithm: "sha256",
		Digest:    "575d810a9fae5f2f0671c9b2c0ce973e46c7207fbe5cb8d1b0d1836a6a0470e3",
	}
	tests := []struct {
		name          string
		field         IngestPredicates
		wantPkg       map[string]*generated.IDorPkgInput
		wantSource    map[string]*generated.IDorSourceInput
		wantArtifact  map[string]*generated.IDorArtifactInput
		wantMaterials map[string]*generated.IDorArtifactInput
		wantBuilder   map[string]*generated.IDorBuilderInput
		wantVuln      map[string]*generated.IDorVulnerabilityInput
		wantLicense   map[string]*generated.IDorLicenseInput
	}{{
		name: "get nouns",
		field: IngestPredicates{
			CertifyScorecard: []CertifyScorecardIngest{
				{
					Source: k8sSource,
					Scorecard: &generated.ScorecardInputSpec{
						Checks: []generated.ScorecardCheckInputSpec{
							{Check: "Binary-Artifacts", Score: 10},
							{Check: "CI-Tests", Score: 10},
							{Check: "Code-Review", Score: 7},
							{Check: "Dangerous-Workflow", Score: 10},
							{Check: "License", Score: 10},
							{Check: "Pinned-Dependencies", Score: 2},
							{Check: "Security-Policy", Score: 10},
							{Check: "Token-Permissions", Score: 10},
							{Check: "Vulnerabilities", Score: 10},
						},
						AggregateScore:   8.9,
						TimeScanned:      toTime("2022-10-06"),
						ScorecardVersion: "v4.7.0",
						ScorecardCommit:  "7cd6406aef0b80a819402e631919293d5eb6adcf",
					},
				},
			},
			IsDependency: []IsDependencyIngest{
				{
					Pkg:    topLevelPack,
					DepPkg: baselayoutPack,
					IsDependency: &generated.IsDependencyInputSpec{
						DependencyType: generated.DependencyTypeUnknown,
						Justification:  "top level package dependency",
					},
				},
				{
					Pkg:    topLevelPack,
					DepPkg: baselayoutdataPack,
					IsDependency: &generated.IsDependencyInputSpec{
						DependencyType: generated.DependencyTypeUnknown,
						Justification:  "top level package dependency",
					},
				},
			},
			IsOccurrence: []IsOccurrenceIngest{
				{
					Pkg:      worldFilePack,
					Artifact: worldFileArtifact,
					IsOccurrence: &generated.IsOccurrenceInputSpec{
						Justification: "spdx file with checksum",
					},
				},
				{
					Src:      k8sSource,
					Artifact: rootFileArtifact,
					IsOccurrence: &generated.IsOccurrenceInputSpec{
						Justification: "spdx file with checksum",
					},
				},
				{
					Pkg:      rootFilePack,
					Artifact: rootFileArtifact,
					IsOccurrence: &generated.IsOccurrenceInputSpec{
						Justification: "spdx file with checksum",
					},
				},
			},
			HasSBOM: []HasSBOMIngest{
				{
					Pkg: topLevelPack,
					HasSBOM: &generated.HasSBOMInputSpec{
						Uri:              "TestSource",
						Algorithm:        "sha256",
						Digest:           "8b5e8212cae084f92ff91f8625a50ea1070738cfc68ecca08bf04d64f64b9feb",
						DownloadLocation: "TestSource",
					},
				},
				{
					Artifact: rootFileArtifact,
					HasSBOM: &generated.HasSBOMInputSpec{
						Uri:              "TestSource",
						Algorithm:        "sha256",
						Digest:           "8b5e8212cae084f92ff91f8625a50ea1070738cfc68ecca08bf04d64f64b9feb",
						DownloadLocation: "TestSource",
					},
				},
			},
			HasSlsa: []HasSlsaIngest{
				{
					Artifact: &generated.ArtifactInputSpec{
						Algorithm: "sha256",
						Digest:    "fe4fe40ac7250263c5dbe1cf3138912f3f416140aa248637a60d65fe22c47da4",
					},
					Builder: &generated.BuilderInputSpec{
						Uri: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v0.0.1",
					},
					Materials: []generated.ArtifactInputSpec{{
						Algorithm: "gitCommit",
						Digest:    "c27d339ee6075c1f744c5d4b200f7901aad2c369",
					}},
					HasSlsa: &generated.SLSAInputSpec{
						BuildType:   "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
						SlsaVersion: "https://slsa.dev/provenance/v1",
						StartedOn:   &slsaStartTime,
						SlsaPredicate: []generated.SLSAPredicateInputSpec{
							{Key: "slsa.buildDefinition.buildType", Value: "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"},
							{Key: "slsa.buildDefinition.externalParameters.inputs.build_id", Value: "1.23456768e+08"},
							{Key: "slsa.buildDefinition.externalParameters.inputs.deploy_target", Value: "deployment_sys_1a"},
							{Key: "slsa.buildDefinition.externalParameters.inputs.perform_deploy", Value: "true"},
							{Key: "slsa.buildDefinition.externalParameters.vars.MASCOT", Value: "Mona"},
							{Key: "slsa.buildDefinition.externalParameters.workflow.path", Value: ".github/workflow/release.yml"},
							{Key: "slsa.buildDefinition.externalParameters.workflow.ref", Value: "refs/heads/main"},
							{Key: "slsa.buildDefinition.externalParameters.workflow.repository", Value: "https://github.com/octocat/hello-world"},
							{Key: "slsa.buildDefinition.internalParameters.github.actor_id", Value: "1234567"},
							{Key: "slsa.buildDefinition.internalParameters.github.event_name", Value: "workflow_dispatch"},
							{Key: "slsa.buildDefinition.resolvedDependencies.0.digest.gitCommit", Value: "c27d339ee6075c1f744c5d4b200f7901aad2c369"},
							{Key: "slsa.buildDefinition.resolvedDependencies.0.uri", Value: "git+https://github.com/octocat/hello-world@refs/heads/main"},
							{Key: "slsa.buildDefinition.resolvedDependencies.1.uri", Value: "https://github.com/actions/virtual-environments/releases/tag/ubuntu20/20220515.1"},
							{Key: "slsa.runDetails.builder.id", Value: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v0.0.1"},
							{Key: "slsa.runDetails.metadata.invocationId", Value: "https://github.com/octocat/hello-world/actions/runs/1536140711/attempts/1"},
							{Key: "slsa.runDetails.metadata.startedOn", Value: "2023-01-01T12:34:56Z"},
						},
					},
				},
			},
			CertifyVuln: []CertifyVulnIngest{
				{
					Pkg: &generated.PkgInputSpec{
						Type:      "maven",
						Namespace: ptrfrom.String("org.apache.logging.log4j"),
						Name:      "log4j-core",
						Version:   ptrfrom.String("2.8.1"),
						Subpath:   ptrfrom.String(""),
					},
					Vulnerability: &generated.VulnerabilityInputSpec{
						Type:            "cve",
						VulnerabilityID: "cve-2023-1944",
					},
					VulnData: &generated.ScanMetadataInput{
						TimeScanned:    tm,
						ScannerUri:     "osv.dev",
						ScannerVersion: "0.0.14",
					},
				},
				{
					Pkg: &generated.PkgInputSpec{
						Type:      "maven",
						Namespace: ptrfrom.String("org.apache.logging.log4j"),
						Name:      "log4j-core",
						Version:   ptrfrom.String("2.8.1"),
						Subpath:   ptrfrom.String(""),
					},
					Vulnerability: &generated.VulnerabilityInputSpec{
						Type:            "osv",
						VulnerabilityID: "ghsa-8489-44mv-ggj8",
					},
					VulnData: &generated.ScanMetadataInput{
						TimeScanned:    tm,
						ScannerUri:     "osv.dev",
						ScannerVersion: "0.0.14",
					},
				},
				{
					Pkg: &generated.PkgInputSpec{
						Type:      "maven",
						Namespace: ptrfrom.String("org.apache.logging.log4j"),
						Name:      "log4j-core",
						Version:   ptrfrom.String("2.8.1"),
						Subpath:   ptrfrom.String(""),
					},
					Vulnerability: &generated.VulnerabilityInputSpec{
						Type:            "osv",
						VulnerabilityID: "ghsa-fxph-q3j8-mv87",
					},
					VulnData: &generated.ScanMetadataInput{
						TimeScanned:    tm,
						ScannerUri:     "osv.dev",
						ScannerVersion: "0.0.14",
					},
				},
				{
					Pkg: &generated.PkgInputSpec{
						Type:      "maven",
						Namespace: ptrfrom.String("org.apache.logging.log4j"),
						Name:      "log4j-core",
						Version:   ptrfrom.String("2.8.1"),
						Subpath:   ptrfrom.String(""),
					},
					Vulnerability: &generated.VulnerabilityInputSpec{
						Type:            "osv",
						VulnerabilityID: "ghsa-jfh8-c2jp-5v3q",
					},
					VulnData: &generated.ScanMetadataInput{
						TimeScanned:    tm,
						ScannerUri:     "osv.dev",
						ScannerVersion: "0.0.14",
					},
				},
				{
					Pkg: &generated.PkgInputSpec{
						Type:      "maven",
						Namespace: ptrfrom.String("org.apache.logging.log4j"),
						Name:      "log4j-core",
						Version:   ptrfrom.String("2.8.1"),
						Subpath:   ptrfrom.String(""),
					},
					Vulnerability: &generated.VulnerabilityInputSpec{
						Type:            "osv",
						VulnerabilityID: "ghsa-p6xc-xr62-6r2g",
					},
					VulnData: &generated.ScanMetadataInput{
						TimeScanned:    tm,
						ScannerUri:     "osv.dev",
						ScannerVersion: "0.0.14",
					},
				},
				{
					Pkg: &generated.PkgInputSpec{
						Type:      "maven",
						Namespace: ptrfrom.String("org.apache.logging.log4j"),
						Name:      "log4j-core",
						Version:   ptrfrom.String("2.8.1"),
						Subpath:   ptrfrom.String(""),
					},
					Vulnerability: &generated.VulnerabilityInputSpec{
						Type:            "osv",
						VulnerabilityID: "ghsa-vwqq-5vrc-xw9h",
					},
					VulnData: &generated.ScanMetadataInput{
						TimeScanned:    tm,
						ScannerUri:     "osv.dev",
						ScannerVersion: "0.0.14",
					},
				},
			},
			VulnEqual: []VulnEqualIngest{
				{
					Vulnerability: &generated.VulnerabilityInputSpec{
						Type:            "osv",
						VulnerabilityID: "cve-2023-1944",
					},
					EqualVulnerability: &generated.VulnerabilityInputSpec{
						Type:            "cve",
						VulnerabilityID: "cve-2023-1944",
					},
					VulnEqual: &generated.VulnEqualInputSpec{
						Justification: "Decoded OSV data",
					},
				},
				{
					Vulnerability: &generated.VulnerabilityInputSpec{
						Type:            "osv",
						VulnerabilityID: "ghsa-7rjr-3q55-vv33",
					},
					EqualVulnerability: &generated.VulnerabilityInputSpec{
						Type:            "ghsa",
						VulnerabilityID: "ghsa-7rjr-3q55-vv33",
					},
					VulnEqual: &generated.VulnEqualInputSpec{
						Justification: "Decoded OSV data",
					},
				},
				{
					Vulnerability: &generated.VulnerabilityInputSpec{
						Type:            "osv",
						VulnerabilityID: "ghsa-8489-44mv-ggj8",
					},
					EqualVulnerability: &generated.VulnerabilityInputSpec{
						Type:            "ghsa",
						VulnerabilityID: "ghsa-8489-44mv-ggj8",
					},
					VulnEqual: &generated.VulnEqualInputSpec{
						Justification: "Decoded OSV data",
					},
				},
				{
					Vulnerability: &generated.VulnerabilityInputSpec{
						Type:            "osv",
						VulnerabilityID: "ghsa-fxph-q3j8-mv87",
					},
					EqualVulnerability: &generated.VulnerabilityInputSpec{
						Type:            "ghsa",
						VulnerabilityID: "ghsa-fxph-q3j8-mv87",
					},
					VulnEqual: &generated.VulnEqualInputSpec{
						Justification: "Decoded OSV data",
					},
				},
				{
					Vulnerability: &generated.VulnerabilityInputSpec{
						Type:            "osv",
						VulnerabilityID: "ghsa-jfh8-c2jp-5v3q",
					},
					EqualVulnerability: &generated.VulnerabilityInputSpec{
						Type:            "ghsa",
						VulnerabilityID: "ghsa-jfh8-c2jp-5v3q",
					},
					VulnEqual: &generated.VulnEqualInputSpec{
						Justification: "Decoded OSV data",
					},
				},
				{
					Vulnerability: &generated.VulnerabilityInputSpec{
						Type:            "osv",
						VulnerabilityID: "ghsa-p6xc-xr62-6r2g",
					},
					EqualVulnerability: &generated.VulnerabilityInputSpec{
						Type:            "ghsa",
						VulnerabilityID: "ghsa-p6xc-xr62-6r2g",
					},
					VulnEqual: &generated.VulnEqualInputSpec{
						Justification: "Decoded OSV data",
					},
				},
			},
			PointOfContact: []PointOfContactIngest{
				{
					Pkg: topLevelPack,
					PkgMatchFlag: generated.MatchFlags{
						Pkg: generated.PkgMatchTypeSpecificVersion,
					},
					//generated.PkgMatchTypeSpecificVersion,
					PointOfContact: &generated.PointOfContactInputSpec{
						Justification: "bad package",
					},
				},
				{
					Src: k8sSource,
					PointOfContact: &generated.PointOfContactInputSpec{
						Justification: "bad source",
					},
				},
				{
					Artifact: &generated.ArtifactInputSpec{
						Algorithm: "sha256",
						Digest:    "fe4fe40ac7250263c5dbe1cf3138912f3f416140aa248637a60d65fe22c47da4",
					},
					PointOfContact: &generated.PointOfContactInputSpec{
						Justification: "bad artifact",
					},
				},
			},
			HasMetadata: []HasMetadataIngest{
				{
					Pkg: topLevelPack,
					PkgMatchFlag: generated.MatchFlags{
						Pkg: generated.PkgMatchTypeSpecificVersion,
					},
					//generated.PkgMatchTypeSpecificVersion,
					HasMetadata: &generated.HasMetadataInputSpec{
						Justification: "bad package",
					},
				},
				{
					Src: k8sSource,
					HasMetadata: &generated.HasMetadataInputSpec{
						Justification: "bad source",
					},
				},
				{
					Artifact: &generated.ArtifactInputSpec{
						Algorithm: "sha256",
						Digest:    "fe4fe40ac7250263c5dbe1cf3138912f3f416140aa248637a60d65fe22c47da4",
					},
					HasMetadata: &generated.HasMetadataInputSpec{
						Justification: "bad artifact",
					},
				},
			},
			CertifyBad: []CertifyBadIngest{
				{
					Pkg: topLevelPack,
					PkgMatchFlag: generated.MatchFlags{
						Pkg: generated.PkgMatchTypeSpecificVersion,
					},
					//generated.PkgMatchTypeSpecificVersion,
					CertifyBad: &generated.CertifyBadInputSpec{
						Justification: "bad package",
					},
				},
				{
					Src: k8sSource,
					CertifyBad: &generated.CertifyBadInputSpec{
						Justification: "bad source",
					},
				},
				{
					Artifact: &generated.ArtifactInputSpec{
						Algorithm: "sha256",
						Digest:    "fe4fe40ac7250263c5dbe1cf3138912f3f416140aa248637a60d65fe22c47da4",
					},
					CertifyBad: &generated.CertifyBadInputSpec{
						Justification: "bad artifact",
					},
				},
			},
			CertifyGood: []CertifyGoodIngest{
				{
					Pkg: topLevelPack,
					PkgMatchFlag: generated.MatchFlags{
						Pkg: generated.PkgMatchTypeSpecificVersion,
					},
					CertifyGood: &generated.CertifyGoodInputSpec{
						Justification: "good package",
					},
				},
				{
					Src: k8sSource,
					CertifyGood: &generated.CertifyGoodInputSpec{
						Justification: "good source",
					},
				},
				{
					Artifact: &generated.ArtifactInputSpec{
						Algorithm: "sha256",
						Digest:    "1234e40ac7250263c5dbe1cf3138912f3f416140aa248637a60d65fe22c47da4",
					},
					CertifyGood: &generated.CertifyGoodInputSpec{
						Justification: "good artifact",
					},
				},
			},
			HasSourceAt: []HasSourceAtIngest{
				{
					Pkg: topLevelPack,
					PkgMatchFlag: generated.MatchFlags{
						Pkg: generated.PkgMatchTypeSpecificVersion,
					},
					Src: k8sSource,
					HasSourceAt: &generated.HasSourceAtInputSpec{
						Justification: "package at this source",
					},
				},
			},
			HashEqual: []HashEqualIngest{
				{
					Artifact: &generated.ArtifactInputSpec{
						Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
						Algorithm: "sha256",
					},
					EqualArtifact: &generated.ArtifactInputSpec{
						Digest:    "7A8F47318E4676DACB0142AFA0B83029CD7BEFD9",
						Algorithm: "sha1",
					},
					HashEqual: &generated.HashEqualInputSpec{
						Justification: "these sha1 and sha256 artifacts are the same",
						Origin:        "Demo ingestion",
						Collector:     "Demo ingestion",
					},
				},
			},
			PkgEqual: []PkgEqualIngest{
				{
					Pkg:      openSSLWithQualifier,
					EqualPkg: openSSL,
					PkgEqual: &generated.PkgEqualInputSpec{
						Justification: "these two openssl packages are the same",
						Origin:        "Demo ingestion",
						Collector:     "Demo ingestion",
					},
				},
			},
			Vex: []VexIngest{
				{
					Pkg: openSSLWithQualifier,
					Vulnerability: &generated.VulnerabilityInputSpec{
						Type:            "ghsa",
						VulnerabilityID: "ghsa-h45f-rjvw-2rv2",
					},
					VexData: &generated.VexStatementInputSpec{
						Status:           generated.VexStatusNotAffected,
						VexJustification: generated.VexJustificationComponentNotPresent,
						KnownSince:       tm,
						Origin:           "Demo ingestion",
						Collector:        "Demo ingestion",
						Description:      ptrfrom.String("this package is not vulnerable to this GHSA"),
						Cvss:             &generated.CVSSInput{VulnImpact: ptrfrom.Float64(2.0), Version: ptrfrom.String("1.0"), AttackString: ptrfrom.String("AttackString")},
					},
				},
				{
					Artifact: &generated.ArtifactInputSpec{
						Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
						Algorithm: "sha256",
					},
					Vulnerability: &generated.VulnerabilityInputSpec{
						Type:            "osv",
						VulnerabilityID: "cve-2018-15710",
					},
					VexData: &generated.VexStatementInputSpec{
						Status:           generated.VexStatusUnderInvestigation,
						VexJustification: generated.VexJustificationNotProvided,
						KnownSince:       tm,
						Origin:           "Demo ingestion",
						Collector:        "Demo ingestion",
						Description:      ptrfrom.String("this artifact is under investigation for this CVE"),
					},
				},
				{
					Artifact: &generated.ArtifactInputSpec{
						Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
						Algorithm: "sha256",
					},
					Vulnerability: &generated.VulnerabilityInputSpec{
						Type:            "cve",
						VulnerabilityID: "cve-2018-43610",
					},
					VexData: &generated.VexStatementInputSpec{
						Status:           generated.VexStatusNotAffected,
						VexJustification: generated.VexJustificationNotProvided,
						Statement:        "this artifact is not vulnerable to this CVE",
						StatusNotes:      "status not affected because code not in execution path",
						KnownSince:       tm,
						Origin:           "Demo ingestion",
						Collector:        "Demo ingestion",
					},
				},
			},
			VulnMetadata: []VulnMetadataIngest{
				{
					Vulnerability: &generated.VulnerabilityInputSpec{
						Type:            "ghsa",
						VulnerabilityID: "ghsa-h45f-rjvw-2rv2",
					},
					VulnMetadata: &generated.VulnerabilityMetadataInputSpec{
						ScoreType:  generated.VulnerabilityScoreTypeCvssv2,
						ScoreValue: 6.8,
						Timestamp:  tm,
						Origin:     "Demo ingestion",
						Collector:  "Demo ingestion",
					},
				},
				{
					Vulnerability: &generated.VulnerabilityInputSpec{
						Type:            "osv",
						VulnerabilityID: "cve-2018-15710",
					},
					VulnMetadata: &generated.VulnerabilityMetadataInputSpec{
						ScoreType:  generated.VulnerabilityScoreTypeCvssv3,
						ScoreValue: 7.8,
						Timestamp:  tm,
						Origin:     "Demo ingestion",
						Collector:  "Demo ingestion",
					},
				},
			},
			CertifyLegal: []CertifyLegalIngest{
				{
					Pkg: maven,
					Declared: []generated.LicenseInputSpec{
						{
							Name:        "asdf",
							ListVersion: ptrfrom.String("1.2.3"),
						},
					},
					Discovered: []generated.LicenseInputSpec{
						{
							Name:        "asdf",
							ListVersion: ptrfrom.String("1.2.3"),
						},
						{
							Name:        "qwer",
							ListVersion: ptrfrom.String("1.2.3"),
						},
					},
					CertifyLegal: &generated.CertifyLegalInputSpec{
						DeclaredLicense:   "asdf",
						DiscoveredLicense: "asdf AND qwer",
						Attribution:       "Copyright Jeff",
						Justification:     "Scanner foo",
						TimeScanned:       toTime("2022-10-06"),
					},
				},
				{
					Pkg: openSSL,
					Declared: []generated.LicenseInputSpec{
						{
							Name:        "qwer",
							ListVersion: ptrfrom.String("1.2.3"),
						},
					},
					Discovered: []generated.LicenseInputSpec{
						{
							Name:        "qwer",
							ListVersion: ptrfrom.String("1.2.3"),
						},
						{
							Name:   "LicenseRef-123",
							Inline: ptrfrom.String("This is the license text."),
						},
					},
					CertifyLegal: &generated.CertifyLegalInputSpec{
						DeclaredLicense:   "qwer",
						DiscoveredLicense: "qwer AND LicenseRef-123",
						Attribution:       "Copyright Jeff",
						Justification:     "Scanner foo",
						TimeScanned:       toTime("2022-10-06"),
					},
				},
			},
		},
		wantPkg: map[string]*generated.IDorPkgInput{
			"alpine::guac-empty-@@::alpine-baselayout-data::3.2.0-r22::guac-empty-@@?arch=x86_64&distro=alpine-3.16.2&upstream=alpine-baselayout&":            {PackageInput: baselayoutdataPack},
			"alpine::guac-empty-@@::alpine-baselayout::3.2.0-r22::guac-empty-@@?arch=x86_64&distro=alpine-3.16.2&upstream=alpine-baselayout&":                 {PackageInput: baselayoutPack},
			"conan::openssl.org::openssl2::3.0.3::guac-empty-@@?":                                                                                             {PackageInput: openSSL},
			"conan::openssl.org::openssl::3.0.3::guac-empty-@@?channel=stable&user=bincrafters&":                                                              {PackageInput: openSSLWithQualifier},
			"guac::files::sha256:575d810a9fae5f2f0671c9b2c0ce973e46c7207fbe5cb8d1b0d1836a6a0470e3::guac-empty-@@::guac-empty-@@?filename=/etc/crontabs/root&": {PackageInput: rootFilePack},
			"guac::files::sha256:713e3907167dce202d7c16034831af3d670191382a3e9026e0ac0a4023013201::guac-empty-@@::guac-empty-@@?filename=/etc/apk/world&":     {PackageInput: worldFilePack},
			"guac::spdx/gcr.io/google-containers::alpine-latest::guac-empty-@@::guac-empty-@@?":                                                               {PackageInput: topLevelPack},
			"maven::org.apache.logging.log4j::log4j-core::2.8.1::guac-empty-@@?":                                                                              {PackageInput: maven}},
		wantSource: map[string]*generated.IDorSourceInput{
			"git::github.com/kubernetes::kubernetes::::5835544ca568b757a8ecae5c153f317e5736700e?": {SourceInput: k8sSource}},
		wantArtifact: map[string]*generated.IDorArtifactInput{
			"sha1:7a8f47318e4676dacb0142afa0b83029cd7befd9": {ArtifactInput: &generated.ArtifactInputSpec{
				Algorithm: "sha1",
				Digest:    "7A8F47318E4676DACB0142AFA0B83029CD7BEFD9",
			}},
			"sha256:1234e40ac7250263c5dbe1cf3138912f3f416140aa248637a60d65fe22c47da4": {ArtifactInput: &generated.ArtifactInputSpec{
				Algorithm: "sha256",
				Digest:    "1234e40ac7250263c5dbe1cf3138912f3f416140aa248637a60d65fe22c47da4",
			}},
			"sha256:575d810a9fae5f2f0671c9b2c0ce973e46c7207fbe5cb8d1b0d1836a6a0470e3": {ArtifactInput: &generated.ArtifactInputSpec{
				Algorithm: "sha256",
				Digest:    "575d810a9fae5f2f0671c9b2c0ce973e46c7207fbe5cb8d1b0d1836a6a0470e3",
			}},
			"sha256:6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf": {ArtifactInput: &generated.ArtifactInputSpec{
				Algorithm: "sha256",
				Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
			}},
			"sha256:713e3907167dce202d7c16034831af3d670191382a3e9026e0ac0a4023013201": {ArtifactInput: &generated.ArtifactInputSpec{
				Algorithm: "sha256",
				Digest:    "713e3907167dce202d7c16034831af3d670191382a3e9026e0ac0a4023013201",
			}},

			"sha256:fe4fe40ac7250263c5dbe1cf3138912f3f416140aa248637a60d65fe22c47da4": {ArtifactInput: &generated.ArtifactInputSpec{
				Algorithm: "sha256",
				Digest:    "fe4fe40ac7250263c5dbe1cf3138912f3f416140aa248637a60d65fe22c47da4",
			}},
		},
		wantMaterials: map[string]*generated.IDorArtifactInput{
			"gitcommit:c27d339ee6075c1f744c5d4b200f7901aad2c369": {ArtifactInput: &generated.ArtifactInputSpec{
				Algorithm: "gitCommit",
				Digest:    "c27d339ee6075c1f744c5d4b200f7901aad2c369",
			}},
		},
		wantBuilder: map[string]*generated.IDorBuilderInput{
			"https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v0.0.1": {BuilderInput: &generated.BuilderInputSpec{
				Uri: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v0.0.1",
			}},
		},
		wantVuln: map[string]*generated.IDorVulnerabilityInput{
			"cve::cve-2018-43610":       {VulnerabilityInput: &generated.VulnerabilityInputSpec{Type: "cve", VulnerabilityID: "cve-2018-43610"}},
			"cve::cve-2023-1944":        {VulnerabilityInput: &generated.VulnerabilityInputSpec{Type: "cve", VulnerabilityID: "cve-2023-1944"}},
			"ghsa::ghsa-7rjr-3q55-vv33": {VulnerabilityInput: &generated.VulnerabilityInputSpec{Type: "ghsa", VulnerabilityID: "ghsa-7rjr-3q55-vv33"}},
			"ghsa::ghsa-8489-44mv-ggj8": {VulnerabilityInput: &generated.VulnerabilityInputSpec{Type: "ghsa", VulnerabilityID: "ghsa-8489-44mv-ggj8"}},
			"ghsa::ghsa-fxph-q3j8-mv87": {VulnerabilityInput: &generated.VulnerabilityInputSpec{Type: "ghsa", VulnerabilityID: "ghsa-fxph-q3j8-mv87"}},
			"ghsa::ghsa-h45f-rjvw-2rv2": {VulnerabilityInput: &generated.VulnerabilityInputSpec{Type: "ghsa", VulnerabilityID: "ghsa-h45f-rjvw-2rv2"}},
			"ghsa::ghsa-jfh8-c2jp-5v3q": {VulnerabilityInput: &generated.VulnerabilityInputSpec{Type: "ghsa", VulnerabilityID: "ghsa-jfh8-c2jp-5v3q"}},
			"ghsa::ghsa-p6xc-xr62-6r2g": {VulnerabilityInput: &generated.VulnerabilityInputSpec{Type: "ghsa", VulnerabilityID: "ghsa-p6xc-xr62-6r2g"}},
			"osv::cve-2018-15710":       {VulnerabilityInput: &generated.VulnerabilityInputSpec{Type: "osv", VulnerabilityID: "cve-2018-15710"}},
			"osv::cve-2023-1944":        {VulnerabilityInput: &generated.VulnerabilityInputSpec{Type: "osv", VulnerabilityID: "cve-2023-1944"}},
			"osv::ghsa-7rjr-3q55-vv33":  {VulnerabilityInput: &generated.VulnerabilityInputSpec{Type: "osv", VulnerabilityID: "ghsa-7rjr-3q55-vv33"}},
			"osv::ghsa-8489-44mv-ggj8":  {VulnerabilityInput: &generated.VulnerabilityInputSpec{Type: "osv", VulnerabilityID: "ghsa-8489-44mv-ggj8"}},
			"osv::ghsa-fxph-q3j8-mv87":  {VulnerabilityInput: &generated.VulnerabilityInputSpec{Type: "osv", VulnerabilityID: "ghsa-fxph-q3j8-mv87"}},
			"osv::ghsa-jfh8-c2jp-5v3q":  {VulnerabilityInput: &generated.VulnerabilityInputSpec{Type: "osv", VulnerabilityID: "ghsa-jfh8-c2jp-5v3q"}},
			"osv::ghsa-p6xc-xr62-6r2g":  {VulnerabilityInput: &generated.VulnerabilityInputSpec{Type: "osv", VulnerabilityID: "ghsa-p6xc-xr62-6r2g"}},
			"osv::ghsa-vwqq-5vrc-xw9h":  {VulnerabilityInput: &generated.VulnerabilityInputSpec{Type: "osv", VulnerabilityID: "ghsa-vwqq-5vrc-xw9h"}},
		},
		wantLicense: map[string]*generated.IDorLicenseInput{
			"LicenseRef-123": {LicenseInput: &generated.LicenseInputSpec{Name: "LicenseRef-123", Inline: ptrfrom.String("This is the license text.")}},
			"asdf:1.2.3":     {LicenseInput: &generated.LicenseInputSpec{Name: "asdf", ListVersion: ptrfrom.String("1.2.3")}},
			"qwer:1.2.3":     {LicenseInput: &generated.LicenseInputSpec{Name: "qwer", ListVersion: ptrfrom.String("1.2.3")}},
		},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := tt.field
			s, _ := json.Marshal(tt.field)
			fmt.Printf("%s\n", s)
			gotPkgs := i.GetPackages(ctx)
			pkgSort := func(a, b *generated.PkgInputSpec) bool { return a.Name < b.Name }
			if diff := cmp.Diff(tt.wantPkg, gotPkgs, cmpopts.SortSlices(pkgSort)); diff != "" {
				t.Errorf("Unexpected GetPackages results. (-want +got):\n%s", diff)
			}

			gotSources := i.GetSources(ctx)
			srcSort := func(a, b *generated.SourceInputSpec) bool { return a.Name < b.Name }
			if diff := cmp.Diff(tt.wantSource, gotSources, cmpopts.SortSlices(srcSort)); diff != "" {
				t.Errorf("Unexpected GetSources results. (-want +got):\n%s", diff)
			}

			gotArtifacts := i.GetArtifacts(ctx)
			artSort := func(a, b *generated.ArtifactInputSpec) bool { return a.Digest < b.Digest }
			if diff := cmp.Diff(tt.wantArtifact, gotArtifacts, cmpopts.SortSlices(artSort)); diff != "" {
				t.Errorf("Unexpected GetArtifacts results. (-want +got):\n%s", diff)
			}

			gotMaterials := i.GetMaterials(ctx)
			matSort := func(a, b *generated.ArtifactInputSpec) bool { return a.Digest < b.Digest }
			if diff := cmp.Diff(tt.wantMaterials, gotMaterials, cmpopts.SortSlices(matSort)); diff != "" {
				t.Errorf("Unexpected GetMaterials results. (-want +got):\n%s", diff)
			}

			gotBuilders := i.GetBuilders(ctx)
			buildSort := func(a, b *generated.BuilderInputSpec) bool { return a.Uri < b.Uri }
			if diff := cmp.Diff(tt.wantBuilder, gotBuilders, cmpopts.SortSlices(buildSort)); diff != "" {
				t.Errorf("Unexpected GetBuilders results. (-want +got):\n%s", diff)
			}

			gotVulns := i.GetVulnerabilities(ctx)
			vulnSort := func(a, b *generated.VulnerabilityInputSpec) bool {
				return helpers.GetKey[*generated.VulnerabilityInputSpec, helpers.VulnIds](a, helpers.VulnClientKey).VulnerabilityID < helpers.GetKey[*generated.VulnerabilityInputSpec, helpers.VulnIds](b, helpers.VulnClientKey).VulnerabilityID
			}
			if diff := cmp.Diff(tt.wantVuln, gotVulns, cmpopts.SortSlices(vulnSort)); diff != "" {
				t.Errorf("Unexpected gotVulns results. (-want +got):\n%s", diff)
			}

			gotLicenses := i.GetLicenses(ctx)
			licSort := func(a, b generated.LicenseInputSpec) bool { return a.Name < b.Name }
			if diff := cmp.Diff(tt.wantLicense, gotLicenses, cmpopts.SortSlices(licSort)); diff != "" {
				t.Errorf("Unexpected GetLicenses results. (-want +got):\n%s", diff)
			}
		})
	}
}

func toTime(s string) time.Time {
	timeScanned, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return timeScanned
}
