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

package arangodb

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/keyvalue"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/helpers"
)

const (
	statusStr           string = "status"
	vexJustificationStr string = "vexJustification"
	statementStr        string = "statement"
	statusNotesStr      string = "statusNotes"
	knownSinceStr       string = "knownSince"
	descriptionStr      string = "description"
	priorityStr         string = "priority"
	reachableCodeStr    string = "reachableCode"
	exploitsStr         string = "exploits"
	cweStr              string = "cwe"
	cvssStr             string = "cvss"
)

func (c *arangoClient) CertifyVEXStatementList(ctx context.Context, certifyVEXStatementSpec model.CertifyVEXStatementSpec, after *string, first *int) (*model.VEXConnection, error) {
	return nil, fmt.Errorf("not implemented: CertifyVEXStatementList")
}

func (c *arangoClient) CertifyVEXStatement(ctx context.Context, certifyVEXStatementSpec *model.CertifyVEXStatementSpec) ([]*model.CertifyVEXStatement, error) {

	if certifyVEXStatementSpec != nil && certifyVEXStatementSpec.ID != nil {
		vex, err := c.buildCertifyVexByID(ctx, *certifyVEXStatementSpec.ID, certifyVEXStatementSpec)
		if err != nil {
			return nil, fmt.Errorf("buildCertifyVexByID failed with an error: %w", err)
		}
		return []*model.CertifyVEXStatement{vex}, nil
	}

	// TODO (pxp928): Optimize/add other queries based on insput and starting node/edge for most efficient retrieval
	var arangoQueryBuilder *arangoQueryBuilder
	if certifyVEXStatementSpec.Subject != nil {
		var combinedVEX []*model.CertifyVEXStatement
		if certifyVEXStatementSpec.Subject.Package != nil {
			values := map[string]any{}
			arangoQueryBuilder = setPkgVersionMatchValues(certifyVEXStatementSpec.Subject.Package, values)
			arangoQueryBuilder.forOutBound(certifyVexPkgEdgesStr, "certifyVex", "pVersion")
			setVexMatchValues(arangoQueryBuilder, certifyVEXStatementSpec, values)

			pkgVersionVEXs, err := getPkgVexForQuery(ctx, c, arangoQueryBuilder, values)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve package version certifyVex with error: %w", err)
			}

			combinedVEX = append(combinedVEX, pkgVersionVEXs...)
		}
		if certifyVEXStatementSpec.Subject.Artifact != nil {
			values := map[string]any{}
			arangoQueryBuilder = setArtifactMatchValues(certifyVEXStatementSpec.Subject.Artifact, values)
			arangoQueryBuilder.forOutBound(certifyVexArtEdgesStr, "certifyVex", "art")
			setVexMatchValues(arangoQueryBuilder, certifyVEXStatementSpec, values)

			artVEXs, err := getArtifactVexForQuery(ctx, c, arangoQueryBuilder, values)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve artifact certifyVex with error: %w", err)
			}
			combinedVEX = append(combinedVEX, artVEXs...)
		}
		return combinedVEX, nil
	} else {
		values := map[string]any{}
		var combinedVEX []*model.CertifyVEXStatement

		// get packages
		arangoQueryBuilder = newForQuery(certifyVEXsStr, "certifyVex")
		setVexMatchValues(arangoQueryBuilder, certifyVEXStatementSpec, values)
		arangoQueryBuilder.forInBound(certifyVexPkgEdgesStr, "pVersion", "certifyVex")
		arangoQueryBuilder.forInBound(pkgHasVersionStr, "pName", "pVersion")
		arangoQueryBuilder.forInBound(pkgHasNameStr, "pNs", "pName")
		arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "pType", "pNs")

		pkgVersionVEXs, err := getPkgVexForQuery(ctx, c, arangoQueryBuilder, values)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve package certifyVex with error: %w", err)
		}
		combinedVEX = append(combinedVEX, pkgVersionVEXs...)

		// get artifacts
		arangoQueryBuilder = newForQuery(certifyVEXsStr, "certifyVex")
		setVexMatchValues(arangoQueryBuilder, certifyVEXStatementSpec, values)
		arangoQueryBuilder.forInBound(certifyVexArtEdgesStr, "art", "certifyVex")

		artVEXs, err := getArtifactVexForQuery(ctx, c, arangoQueryBuilder, values)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve artifact certifyVex with error: %w", err)
		}
		combinedVEX = append(combinedVEX, artVEXs...)

		return combinedVEX, nil
	}
}

func getPkgVexForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any) ([]*model.CertifyVEXStatement, error) {
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		'pkgVersion': {
			"type_id": pType._id,
			"type": pType.type,
			"namespace_id": pNs._id,
			"namespace": pNs.namespace,
			"name_id": pName._id,
			"name": pName.name,
			"version_id": pVersion._id,
			"version": pVersion.version,
			"subpath": pVersion.subpath,
			"qualifier_list": pVersion.qualifier_list
		},
		'vulnerability': {
			"type_id": vType._id,
		    "type": vType.type,
		    "vuln_id": vVulnID._id,
		    "vuln": vVulnID.vulnerabilityID
		},
		'certifyVex_id': certifyVex._id,
		'status': certifyVex.status,
		'vexJustification': certifyVex.vexJustification,
		'statement': certifyVex.statement,
		'statusNotes': certifyVex.statusNotes,
		'knownSince': certifyVex.knownSince,
		'collector': certifyVex.collector,
		'origin': certifyVex.origin,
		'documentRef': certifyVex.documentRef,
		'description': certifyVex.description,
		'exploits': certifyVex.exploits,
		'cwe': certifyVex.cwe,
		'reachableCode': certifyVex.reachableCode,
		'priority': certifyVex.priority,
		'cvss': certifyVex.cvss
	  }`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "CertifyVEXStatement")
	if err != nil {
		return nil, fmt.Errorf("failed to query for CertifyVEXStatement: %w", err)
	}
	defer cursor.Close()

	return getCertifyVexFromCursor(ctx, cursor, false)
}

func getArtifactVexForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any) ([]*model.CertifyVEXStatement, error) {
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		'artifact': {
			'id': art._id,
			'algorithm': art.algorithm,
			'digest': art.digest
		},
		'vulnerability': {
			"type_id": vType._id,
		    "type": vType.type,
		    "vuln_id": vVulnID._id,
		    "vuln": vVulnID.vulnerabilityID
		},
		'certifyVex_id': certifyVex._id,
		'status': certifyVex.status,
		'vexJustification': certifyVex.vexJustification,
		'statement': certifyVex.statement,
		'statusNotes': certifyVex.statusNotes,
		'knownSince': certifyVex.knownSince,
		'collector': certifyVex.collector,
		'origin': certifyVex.origin,
		'documentRef': certifyVex.documentRef,
		'description': certifyVex.description,
		'exploits': certifyVex.exploits,
		'cwe': certifyVex.cwe,
		'priority': certifyVex.priority,
		'cvss': certifyVex.cvss,
		'reachableCode': certifyVex.reachableCode
	}`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "CertifyVEXStatement")
	if err != nil {
		return nil, fmt.Errorf("failed to query for CertifyVEXStatement: %w", err)
	}
	defer cursor.Close()

	return getCertifyVexFromCursor(ctx, cursor, false)
}

func setVexMatchValues(arangoQueryBuilder *arangoQueryBuilder, certifyVexSpec *model.CertifyVEXStatementSpec, queryValues map[string]any) {
	if certifyVexSpec.ID != nil {
		arangoQueryBuilder.filter("certifyVex", "_id", "==", "@id")
		queryValues["id"] = *certifyVexSpec.ID
	}
	if certifyVexSpec.Status != nil {
		arangoQueryBuilder.filter("certifyVex", statusStr, "==", "@"+statusStr)
		queryValues[statusStr] = *certifyVexSpec.Status
	}
	if certifyVexSpec.VexJustification != nil {
		arangoQueryBuilder.filter("certifyVex", vexJustificationStr, "==", "@"+vexJustificationStr)
		queryValues[vexJustificationStr] = *certifyVexSpec.VexJustification
	}
	if certifyVexSpec.Statement != nil {
		arangoQueryBuilder.filter("certifyVex", statementStr, "==", "@"+statementStr)
		queryValues[statementStr] = *certifyVexSpec.Statement
	}
	if certifyVexSpec.StatusNotes != nil {
		arangoQueryBuilder.filter("certifyVex", statusNotesStr, "==", "@"+statusNotesStr)
		queryValues[statusNotesStr] = *certifyVexSpec.StatusNotes
	}
	if certifyVexSpec.KnownSince != nil {
		arangoQueryBuilder.filter("certifyVex", knownSinceStr, "==", "@"+knownSinceStr)
		queryValues[knownSinceStr] = certifyVexSpec.KnownSince.UTC()
	}
	if certifyVexSpec.Origin != nil {
		arangoQueryBuilder.filter("certifyVex", origin, "==", "@"+origin)
		queryValues[origin] = *certifyVexSpec.Origin
	}
	if certifyVexSpec.Collector != nil {
		arangoQueryBuilder.filter("certifyVex", collector, "==", "@"+collector)
		queryValues[collector] = *certifyVexSpec.Collector
	}
	if certifyVexSpec.DocumentRef != nil {
		arangoQueryBuilder.filter("certifyVex", docRef, "==", "@"+docRef)
		queryValues[docRef] = *certifyVexSpec.DocumentRef
	}
	if certifyVexSpec.Description != nil {
		arangoQueryBuilder.filter("certifyVex", descriptionStr, "==", "@"+descriptionStr)
		queryValues[descriptionStr] = *certifyVexSpec.Description
	}
	if certifyVexSpec.ReachableCode != nil {
		arangoQueryBuilder.filter("certifyVex", reachableCodeStr, "==", "@"+reachableCodeStr)
		queryValues[reachableCodeStr] = keyvalue.ConvertReachableCodeInputs(certifyVexSpec.ReachableCode)
	}
	if certifyVexSpec.Exploits != nil {
		arangoQueryBuilder.filter("certifyVex", exploitsStr, "==", "@"+exploitsStr)
		queryValues[exploitsStr] = keyvalue.ConvertExploitsInputs(certifyVexSpec.Exploits)
	}
	if certifyVexSpec.Cwe != nil {
		arangoQueryBuilder.filter("certifyVex", cweStr, "==", "@"+cweStr)
		queryValues[cweStr] = keyvalue.ConvertCwesInputSpecToCwes(certifyVexSpec.Cwe)
	}
	if certifyVexSpec.Priority != nil {
		arangoQueryBuilder.filter("certifyVex", priorityStr, "==", "@"+priorityStr)
		queryValues[priorityStr] = *certifyVexSpec.Priority
	}
	if certifyVexSpec.Cvss != nil {
		arangoQueryBuilder.filter("certifyVex", cvssStr, "==", "@"+cvssStr)
		queryValues[cvssStr] = *certifyVexSpec.Cvss
	}
	if certifyVexSpec.Vulnerability != nil {
		arangoQueryBuilder.forOutBound(certifyVexVulnEdgesStr, "vVulnID", "certifyVex")
		if certifyVexSpec.Vulnerability.ID != nil {
			arangoQueryBuilder.filter("vVulnID", "_id", "==", "@id")
			queryValues["id"] = *certifyVexSpec.Vulnerability.ID
		}
		if certifyVexSpec.Vulnerability.VulnerabilityID != nil {
			arangoQueryBuilder.filter("vVulnID", "vulnerabilityID", "==", "@vulnerabilityID")
			queryValues["vulnerabilityID"] = strings.ToLower(*certifyVexSpec.Vulnerability.VulnerabilityID)
		}
		arangoQueryBuilder.forInBound(vulnHasVulnerabilityIDStr, "vType", "vVulnID")
		if certifyVexSpec.Vulnerability.Type != nil {
			arangoQueryBuilder.filter("vType", "type", "==", "@vulnType")
			queryValues["vulnType"] = strings.ToLower(*certifyVexSpec.Vulnerability.Type)
		}
	} else {
		arangoQueryBuilder.forOutBound(certifyVexVulnEdgesStr, "vVulnID", "certifyVex")
		arangoQueryBuilder.forInBound(vulnHasVulnerabilityIDStr, "vType", "vVulnID")
	}
}

func getVEXStatementQueryValues(pkg *model.PkgInputSpec, artifact *model.ArtifactInputSpec, vulnerability *model.VulnerabilityInputSpec, vexStatement *model.VexStatementInputSpec) map[string]any {
	values := map[string]any{}
	// add guac keys
	if pkg != nil {
		pkgId := helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](pkg, helpers.PkgServerKey)
		values["pkgVersionGuacKey"] = pkgId.VersionId
	} else {
		values["art_algorithm"] = strings.ToLower(artifact.Algorithm)
		values["art_digest"] = strings.ToLower(artifact.Digest)
	}
	if vulnerability != nil {
		vuln := helpers.GetKey[*model.VulnerabilityInputSpec, helpers.VulnIds](vulnerability, helpers.VulnServerKey)
		values["guacVulnKey"] = vuln.VulnerabilityID
	}
	values[statusStr] = vexStatement.Status
	values[vexJustificationStr] = vexStatement.VexJustification
	values[statementStr] = vexStatement.Statement
	values[statusNotesStr] = vexStatement.StatusNotes
	values[knownSinceStr] = vexStatement.KnownSince.UTC()
	values[origin] = vexStatement.Origin
	values[collector] = vexStatement.Collector
	values[docRef] = vexStatement.DocumentRef
	values[descriptionStr] = vexStatement.Description
	values[reachableCodeStr] = vexStatement.ReachableCode
	values[exploitsStr] = vexStatement.Exploits
	values[cweStr] = vexStatement.Cwe
	values[priorityStr] = vexStatement.Priority
	values[cvssStr] = vexStatement.Cvss

	return values
}

func (c *arangoClient) IngestVEXStatements(ctx context.Context, subjects model.PackageOrArtifactInputs, vulnerabilities []*model.IDorVulnerabilityInput, vexStatements []*model.VexStatementInputSpec) ([]string, error) {
	if len(subjects.Artifacts) > 0 {
		var listOfValues []map[string]any

		for i := range subjects.Artifacts {
			listOfValues = append(listOfValues, getVEXStatementQueryValues(nil, subjects.Artifacts[i].ArtifactInput, vulnerabilities[i].VulnerabilityInput, vexStatements[i]))
		}

		var documents []string
		for _, val := range listOfValues {
			bs, _ := json.Marshal(val)
			documents = append(documents, string(bs))
		}

		queryValues := map[string]any{}
		queryValues["documents"] = fmt.Sprint(strings.Join(documents, ","))

		var sb strings.Builder

		sb.WriteString("for doc in [")
		for i, val := range listOfValues {
			bs, _ := json.Marshal(val)
			if i == len(listOfValues)-1 {
				sb.WriteString(string(bs))
			} else {
				sb.WriteString(string(bs) + ",")
			}
		}
		sb.WriteString("]")

		query := `LET artifact = FIRST(FOR art IN artifacts FILTER art.algorithm == doc.art_algorithm FILTER art.digest == doc.art_digest RETURN art)

		LET firstVuln = FIRST(
			FOR vVulnID in vulnerabilities
			  FILTER vVulnID.guacKey == doc.guacVulnKey
			RETURN {
			  "vuln_id": vVulnID._id,
			  "vuln_key": vVulnID._key
			}
		)
		  
		LET certifyVex = FIRST(
			UPSERT { artifactID:artifact._id, vulnerabilityID:firstVuln.vuln_id, status:doc.status, vexJustification:doc.vexJustification, statement:doc.statement, statusNotes:doc.statusNotes, knownSince:doc.knownSince, collector:doc.collector, origin:doc.origin, documentRef:doc.documentRef, description:doc.description, reachableCode:doc.reachableCode, exploits:doc.exploits, cwe:doc.cwe, priority:doc.priority, cvss:doc.cvss } 
				INSERT {artifactID:artifact._id, vulnerabilityID:firstVuln.vuln_id, status:doc.status, vexJustification:doc.vexJustification, statement:doc.statement, statusNotes:doc.statusNotes, knownSince:doc.knownSince, collector:doc.collector, origin:doc.origin, documentRef:doc.documentRef, description:doc.description, reachableCode:doc.reachableCode, exploits:doc.exploits, cwe:doc.cwe, priority:doc.priority, cvss:doc.cvss } 
				UPDATE {} IN certifyVEXs
				RETURN {
					'_id': NEW._id,
					'_key': NEW._key
				}
		)
		
		INSERT { _key: CONCAT("certifyVexArtEdges", artifact._key, certifyVex._key), _from: artifact._id, _to: certifyVex._id } INTO certifyVexArtEdges OPTIONS { overwriteMode: "ignore" }
		INSERT { _key: CONCAT("certifyVexVulnEdges", certifyVex._key, firstVuln.vuln_key), _from: certifyVex._id, _to: firstVuln.vuln_id } INTO certifyVexVulnEdges OPTIONS { overwriteMode: "ignore" }

		RETURN { 'certifyVex_id': certifyVex._id }`

		sb.WriteString(query)

		cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestVEXStatements")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest artifact VEX: %w", err)
		}
		defer cursor.Close()
		vexList, err := getCertifyVexFromCursor(ctx, cursor, true)
		if err != nil {
			return nil, fmt.Errorf("failed to get VEX from arango cursor: %w", err)
		}

		var vexIDList []string
		for _, ingestedVex := range vexList {
			vexIDList = append(vexIDList, ingestedVex.ID)
		}

		return vexIDList, nil

	} else if len(subjects.Packages) > 0 {

		var listOfValues []map[string]any

		for i := range subjects.Packages {
			listOfValues = append(listOfValues, getVEXStatementQueryValues(subjects.Packages[i].PackageInput, nil, vulnerabilities[i].VulnerabilityInput, vexStatements[i]))
		}

		var documents []string
		for _, val := range listOfValues {
			bs, _ := json.Marshal(val)
			documents = append(documents, string(bs))
		}

		queryValues := map[string]any{}
		queryValues["documents"] = fmt.Sprint(strings.Join(documents, ","))

		var sb strings.Builder

		sb.WriteString("for doc in [")
		for i, val := range listOfValues {
			bs, _ := json.Marshal(val)
			if i == len(listOfValues)-1 {
				sb.WriteString(string(bs))
			} else {
				sb.WriteString(string(bs) + ",")
			}
		}
		sb.WriteString("]")

		query := `
		LET firstPkg = FIRST(
			FOR pVersion in pkgVersions
			  FILTER pVersion.guacKey == doc.pkgVersionGuacKey	
			RETURN {
			  'version_id': pVersion._id,
			  'version_key': pVersion._key
			}
		)

		LET firstVuln = FIRST(
			FOR vVulnID in vulnerabilities
			  FILTER vVulnID.guacKey == doc.guacVulnKey
			RETURN {
				"vuln_id": vVulnID._id,
				"vuln_key": vVulnID._key
			}
		)
		  
		LET certifyVex = FIRST(
			UPSERT { packageID:firstPkg.version_id, vulnerabilityID:firstVuln.vuln_id, status:doc.status, vexJustification:doc.vexJustification, statement:doc.statement, statusNotes:doc.statusNotes, knownSince:doc.knownSince, collector:doc.collector, origin:doc.origin, documentRef:doc.documentRef, description:doc.description, reachableCode:doc.reachableCode, exploits:doc.exploits, cwe:doc.cwe, priority:doc.priority, cvss:doc.cvss } 
				INSERT {packageID:firstPkg.version_id, vulnerabilityID:firstVuln.vuln_id, status:doc.status, vexJustification:doc.vexJustification, statement:doc.statement, statusNotes:doc.statusNotes, knownSince:doc.knownSince, collector:doc.collector, origin:doc.origin, documentRef:doc.documentRef, description:doc.description, reachableCode:doc.reachableCode, exploits:doc.exploits, cwe:doc.cwe, priority:doc.priority, cvss:doc.cvss } 
				UPDATE {} IN certifyVEXs
				RETURN {
					'_id': NEW._id,
					'_key': NEW._key
				}
		)
		
		INSERT { _key: CONCAT("certifyVexPkgEdges", firstPkg.version_key, certifyVex._key), _from: firstPkg.version_id, _to: certifyVex._id } INTO certifyVexPkgEdges OPTIONS { overwriteMode: "ignore" }
		INSERT { _key: CONCAT("certifyVexVulnEdges", certifyVex._key, firstVuln.vuln_key), _from: certifyVex._id, _to: firstVuln.vuln_id } INTO certifyVexVulnEdges OPTIONS { overwriteMode: "ignore" }
		
		  
		RETURN { 'certifyVex_id': certifyVex._id }`

		sb.WriteString(query)

		cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestVEXStatements")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest package Vex: %w", err)
		}
		defer cursor.Close()

		vexList, err := getCertifyVexFromCursor(ctx, cursor, true)
		if err != nil {
			return nil, fmt.Errorf("failed to get Vex from arango cursor: %w", err)
		}

		var vexIDList []string
		for _, ingestedVex := range vexList {
			vexIDList = append(vexIDList, ingestedVex.ID)
		}

		return vexIDList, nil

	} else {
		return nil, fmt.Errorf("packages or artifacts not specified for IngestVEXStatements")
	}
}

func (c *arangoClient) IngestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.IDorVulnerabilityInput, vexStatement model.VexStatementInputSpec) (string, error) {
	if subject.Artifact != nil {
		query := `
		  LET artifact = FIRST(FOR art IN artifacts FILTER art.algorithm == @art_algorithm FILTER art.digest == @art_digest RETURN art)

		  LET firstVuln = FIRST(
			FOR vVulnID in vulnerabilities
			  FILTER vVulnID.guacKey == @guacVulnKey
			RETURN {
				"vuln_id": vVulnID._id,
				"vuln_key": vVulnID._key
			}
		  )
		  
		  LET certifyVex = FIRST(
			  UPSERT { artifactID:artifact._id, vulnerabilityID:firstVuln.vuln_id, status:@status, vexJustification:@vexJustification, statement:@statement, statusNotes:@statusNotes, knownSince:@knownSince, collector:@collector, origin:@origin, documentRef:@documentRef, description:@description, reachableCode:@reachableCode, exploits:@exploits, cwe:@cwe, priority:@priority, cvss:@cvss } 
				  INSERT {artifactID:artifact._id, vulnerabilityID:firstVuln.vuln_id, status:@status, vexJustification:@vexJustification, statement:@statement, statusNotes:@statusNotes, knownSince:@knownSince, collector:@collector, origin:@origin, documentRef:@documentRef, description:@description, reachableCode:@reachableCode, exploits:@exploits, cweID:@cwe, priority:@priority, cvss:@cvss } 
				  UPDATE {} IN certifyVEXs
				  RETURN {
					'_id': NEW._id,
					'_key': NEW._key
				}
		  )
		  
		  INSERT { _key: CONCAT("certifyVexArtEdges", artifact._key, certifyVex._key), _from: artifact._id, _to: certifyVex._id } INTO certifyVexArtEdges OPTIONS { overwriteMode: "ignore" }
		  INSERT { _key: CONCAT("certifyVexVulnEdges", certifyVex._key, firstVuln.vuln_key), _from: certifyVex._id, _to: firstVuln.vuln_id } INTO certifyVexVulnEdges OPTIONS { overwriteMode: "ignore" }
		  
		  RETURN { 'certifyVex_id': certifyVex._id }`

		cursor, err := executeQueryWithRetry(ctx, c.db, query, getVEXStatementQueryValues(nil, subject.Artifact.ArtifactInput, vulnerability.VulnerabilityInput, &vexStatement), "IngestVEXStatement - Artifact")
		if err != nil {
			return "", fmt.Errorf("failed to ingest VEX: %w", err)
		}
		defer cursor.Close()
		vexList, err := getCertifyVexFromCursor(ctx, cursor, true)
		if err != nil {
			return "", fmt.Errorf("failed to get VEX from arango cursor: %w", err)
		}

		if len(vexList) == 1 {
			return vexList[0].ID, nil
		} else {
			return "", fmt.Errorf("number of VEX ingested is greater than one")
		}
	} else {
		query := `
		LET firstPkg = FIRST(
			FOR pVersion in pkgVersions
			  FILTER pVersion.guacKey == @pkgVersionGuacKey
			RETURN {
				'version_id': pVersion._id,
				'version_key': pVersion._key
			}
		)

		LET firstVuln = FIRST(
			FOR vVulnID in vulnerabilities
			  FILTER vVulnID.guacKey == @guacVulnKey
			RETURN {
				"vuln_id": vVulnID._id,
				"vuln_key": vVulnID._key
			}
		)
		  
		LET certifyVex = FIRST(
			UPSERT { packageID:firstPkg.version_id, vulnerabilityID:firstVuln.vuln_id, status:@status, vexJustification:@vexJustification, statement:@statement, statusNotes:@statusNotes, knownSince:@knownSince, collector:@collector, origin:@origin, documentRef:@documentRef, description:@description, reachableCode:@reachableCode, exploits:@exploits, cwe:@cwe, priority:@priority, cvss:@cvss } 
				INSERT {packageID:firstPkg.version_id, vulnerabilityID:firstVuln.vuln_id, status:@status, vexJustification:@vexJustification, statement:@statement, statusNotes:@statusNotes, knownSince:@knownSince, collector:@collector, origin:@origin, documentRef:@documentRef, description:@description, reachableCode:@reachableCode, exploits:@exploits, cwe:@cwe, priority:@priority, cvss:@cvss } 
				UPDATE {} IN certifyVEXs
				RETURN {
					'_id': NEW._id,
					'_key': NEW._key
				}
		)
		
		INSERT { _key: CONCAT("certifyVexPkgEdges", firstPkg.version_key, certifyVex._key), _from: firstPkg.version_id, _to: certifyVex._id } INTO certifyVexPkgEdges OPTIONS { overwriteMode: "ignore" }
		INSERT { _key: CONCAT("certifyVexVulnEdges", certifyVex._key, firstVuln.vuln_key), _from: certifyVex._id, _to: firstVuln.vuln_id } INTO certifyVexVulnEdges OPTIONS { overwriteMode: "ignore" }
		
		  
		RETURN { 'certifyVex_id': certifyVex._id }`

		cursor, err := executeQueryWithRetry(ctx, c.db, query, getVEXStatementQueryValues(subject.Package.PackageInput, nil, vulnerability.VulnerabilityInput, &vexStatement), "IngestVEXStatement - Package")
		if err != nil {
			return "", fmt.Errorf("failed to create ingest VEX: %w", err)
		}
		defer cursor.Close()

		vexList, err := getCertifyVexFromCursor(ctx, cursor, true)
		if err != nil {
			return "", fmt.Errorf("failed to get VEX from arango cursor: %w", err)
		}

		if len(vexList) == 1 {
			return vexList[0].ID, nil
		} else {
			return "", fmt.Errorf("number of VEX ingested is greater than one")
		}
	}
}

func getCertifyVexFromCursor(ctx context.Context, cursor driver.Cursor, ingestion bool) ([]*model.CertifyVEXStatement, error) {
	type collectedData struct {
		PkgVersion       *dbPkgVersion          `json:"pkgVersion"`
		Artifact         *model.Artifact        `json:"artifact"`
		Vulnerability    *dbVulnID              `json:"vulnerability"`
		CertifyVexId     string                 `json:"certifyVex_id"`
		Status           string                 `json:"status"`
		VexJustification string                 `json:"vexJustification"`
		Statement        string                 `json:"statement"`
		StatusNotes      string                 `json:"statusNotes"`
		KnownSince       time.Time              `json:"knownSince"`
		Collector        string                 `json:"collector"`
		Origin           string                 `json:"origin"`
		DocumentRef      string                 `json:"documentRef"`
		Description      *string                `json:"description"`
		Exploits         *[]model.Exploits      `json:"exploits"`
		Priority         *float64               `json:"priority"`
		Cwe              *[]model.Cwe           `json:"cwe"`
		ReachableCodes   *[]model.ReachableCode `json:"reachableCode"`
		Cvss             *model.Cvss            `json:"cvss"`
	}

	var createdValues []collectedData
	for {
		var doc collectedData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to package Vex from cursor: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	var certifyVexList []*model.CertifyVEXStatement
	for _, createdValue := range createdValues {
		var pkg *model.Package = nil
		if createdValue.PkgVersion != nil {
			pkg = generateModelPackage(createdValue.PkgVersion.TypeID, createdValue.PkgVersion.PkgType, createdValue.PkgVersion.NamespaceID, createdValue.PkgVersion.Namespace, createdValue.PkgVersion.NameID,
				createdValue.PkgVersion.Name, createdValue.PkgVersion.VersionID, createdValue.PkgVersion.Version, createdValue.PkgVersion.Subpath, createdValue.PkgVersion.QualifierList)
		}

		certifyVex := &model.CertifyVEXStatement{
			ID:               createdValue.CertifyVexId,
			Status:           model.VexStatus(createdValue.Status),
			VexJustification: model.VexJustification(createdValue.VexJustification),
			Statement:        createdValue.Statement,
			StatusNotes:      createdValue.StatusNotes,
			KnownSince:       createdValue.KnownSince,
			Origin:           createdValue.Origin,
			Collector:        createdValue.Collector,
			DocumentRef:      createdValue.DocumentRef,
		}
		if pkg != nil {
			certifyVex.Subject = pkg
		} else if createdValue.Artifact != nil {
			certifyVex.Subject = createdValue.Artifact
		} else {
			if !ingestion {
				return nil, fmt.Errorf("failed to get subject from cursor for certifyVex")
			}
		}

		if createdValue.Cvss != nil {
			certifyVex.Cvss = createdValue.Cvss
		}

		if createdValue.Description != nil {
			certifyVex.Description = createdValue.Description
		}

		if createdValue.Priority != nil {
			certifyVex.Priority = createdValue.Priority
		}

		if createdValue.Exploits != nil {
			exploits := []*model.Exploits{}
			for _, exploit := range *createdValue.Exploits {
				exploits = append(exploits, &exploit)
			}
			certifyVex.Exploits = exploits
		}

		if createdValue.Cwe != nil {
			cwes := []*model.Cwe{}
			for _, cwe := range *createdValue.Cwe {
				cwes = append(cwes, &cwe)
			}
			certifyVex.Cwe = cwes
		}

		if createdValue.ReachableCodes != nil {
			reachableCodes := []*model.ReachableCode{}
			for _, reachableCode := range *createdValue.ReachableCodes {
				reachableCodes = append(reachableCodes, &reachableCode)
			}
			certifyVex.ReachableCode = reachableCodes
		}

		if createdValue.Vulnerability != nil {
			vuln := &model.Vulnerability{
				ID:   createdValue.Vulnerability.VulnID,
				Type: createdValue.Vulnerability.VulnType,
				VulnerabilityIDs: []*model.VulnerabilityID{
					{
						ID:              createdValue.Vulnerability.VulnID,
						VulnerabilityID: createdValue.Vulnerability.Vuln,
					},
				},
			}
			certifyVex.Vulnerability = vuln
		} else {
			if !ingestion {
				return nil, fmt.Errorf("failed to get vulnerability from cursor for scorecard")
			}
		}

		certifyVexList = append(certifyVexList, certifyVex)
	}
	return certifyVexList, nil
}

func (c *arangoClient) buildCertifyVexByID(ctx context.Context, id string, filter *model.CertifyVEXStatementSpec) (*model.CertifyVEXStatement, error) {
	if filter != nil && filter.ID != nil {
		if *filter.ID != id {
			return nil, fmt.Errorf("ID does not match filter")
		}
	}

	idSplit := strings.Split(id, "/")
	if len(idSplit) != 2 {
		return nil, fmt.Errorf("invalid ID: %s", id)
	}

	if idSplit[0] == certifyVEXsStr {
		if filter != nil {
			filter.ID = ptrfrom.String(id)
		} else {
			filter = &model.CertifyVEXStatementSpec{
				ID: ptrfrom.String(id),
			}
		}
		return c.queryCertifyVexNodeByID(ctx, filter)
	} else {
		return nil, fmt.Errorf("id type does not match for certifyVex query: %s", id)
	}
}

func (c *arangoClient) queryCertifyVexNodeByID(ctx context.Context, filter *model.CertifyVEXStatementSpec) (*model.CertifyVEXStatement, error) {
	values := map[string]any{}
	arangoQueryBuilder := newForQuery(certifyVEXsStr, "certifyVex")
	setVexMatchValues(arangoQueryBuilder, filter, values)
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN certifyVex`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "queryCertifyVexNodeByID")
	if err != nil {
		return nil, fmt.Errorf("failed to query for certifyVex: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type dbVex struct {
		VexID            string                `json:"_id"`
		PackageID        *string               `json:"packageID"`
		ArtifactID       *string               `json:"artifactID"`
		VulnerabilityID  string                `json:"vulnerabilityID"`
		Status           string                `json:"status"`
		VexJustification string                `json:"vexJustification"`
		Statement        string                `json:"statement"`
		StatusNotes      string                `json:"statusNotes"`
		KnownSince       time.Time             `json:"knownSince"`
		Collector        string                `json:"collector"`
		Origin           string                `json:"origin"`
		DocumentRef      string                `json:"documentRef"`
		Description      string                `json:"description"`
		Priority         float64               `json:"priority"`
		ReachableCode    []model.ReachableCode `json:"reachableCode"`
		Exploits         []model.Exploits      `json:"exploits"`
		Cwe              []model.Cwe           `json:"cwe"`
		Cvss             model.Cvss            `json:"cvss"`
	}

	var collectedValues []dbVex
	for {
		var doc dbVex
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to certifyVex from cursor: %w", err)
			}
		} else {
			collectedValues = append(collectedValues, doc)
		}
	}

	if len(collectedValues) != 1 {
		return nil, fmt.Errorf("number of certifyVex nodes found for ID: %s is greater than one", *filter.ID)
	}

	vex := &model.CertifyVEXStatement{
		Status:           model.VexStatus(collectedValues[0].Status),
		VexJustification: model.VexJustification(collectedValues[0].VexJustification),
		Statement:        collectedValues[0].Statement,
		StatusNotes:      collectedValues[0].StatusNotes,
		KnownSince:       collectedValues[0].KnownSince,
		Origin:           collectedValues[0].Origin,
		Collector:        collectedValues[0].Collector,
		DocumentRef:      collectedValues[0].DocumentRef,
		Description:      &collectedValues[0].Description,
		ReachableCode:    keyvalue.ConvertReachableCodeToPointers(collectedValues[0].ReachableCode),
		Exploits:         keyvalue.ConvertExploitToPointers(collectedValues[0].Exploits),
		Priority:         &collectedValues[0].Priority,
		Cwe:              keyvalue.ConvertCwesToPointers(collectedValues[0].Cwe),
		Cvss:             &collectedValues[0].Cvss,
	}

	builtVuln, err := c.buildVulnResponseByID(ctx, collectedValues[0].VulnerabilityID, filter.Vulnerability)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerability from ID: %s, with error: %w", collectedValues[0].VulnerabilityID, err)
	}
	vex.Vulnerability = builtVuln

	if collectedValues[0].PackageID != nil {
		var builtPackage *model.Package
		if filter.Subject != nil && filter.Subject.Package != nil {
			builtPackage, err = c.buildPackageResponseFromID(ctx, *collectedValues[0].PackageID, filter.Subject.Package)
			if err != nil {
				return nil, fmt.Errorf("failed to get package from ID: %s, with error: %w", *collectedValues[0].PackageID, err)
			}
		} else {
			builtPackage, err = c.buildPackageResponseFromID(ctx, *collectedValues[0].PackageID, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to get package from ID: %s, with error: %w", *collectedValues[0].PackageID, err)
			}
		}
		vex.Subject = builtPackage
	} else if collectedValues[0].ArtifactID != nil {
		var builtArtifact *model.Artifact
		if filter.Subject != nil && filter.Subject.Artifact != nil {
			builtArtifact, err = c.buildArtifactResponseByID(ctx, *collectedValues[0].ArtifactID, filter.Subject.Artifact)
			if err != nil {
				return nil, fmt.Errorf("failed to get artifact from ID: %s, with error: %w", *collectedValues[0].ArtifactID, err)
			}
		} else {
			builtArtifact, err = c.buildArtifactResponseByID(ctx, *collectedValues[0].ArtifactID, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to get artifact from ID: %s, with error: %w", *collectedValues[0].ArtifactID, err)
			}
		}
		vex.Subject = builtArtifact
	} else {
		return nil, fmt.Errorf("failed to get subject from certifyVEXStatement")
	}
	return vex, nil
}

func (c *arangoClient) certifyVexNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]string, error) {
	out := make([]string, 0, 2)
	if allowedEdges[model.EdgeCertifyVexStatementPackage] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(certifyVEXsStr, "certifyVex")
		setVexMatchValues(arangoQueryBuilder, &model.CertifyVEXStatementSpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  certifyVex.packageID }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "certifyVexNeighbors - package")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeCertifyVexStatementArtifact] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(certifyVEXsStr, "certifyVex")
		setVexMatchValues(arangoQueryBuilder, &model.CertifyVEXStatementSpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  certifyVex.artifactID }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "certifyVexNeighbors - artifact")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeCertifyVexStatementVulnerability] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(certifyVEXsStr, "certifyVex")
		setVexMatchValues(arangoQueryBuilder, &model.CertifyVEXStatementSpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  certifyVex.vulnerabilityID }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "certifyVexNeighbors - vulnerability")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}

	return out, nil
}
