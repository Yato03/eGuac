package evex

import (
	"time"

	"github.com/openvex/go-vex/pkg/vex"
)

// Vulnerability define the details of the vulnerability.
type Vulnerability struct {
	ID          string `json:"@id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CVSS        *CVSS  `json:"CVSS,omitempty"`
	CWEs        []CWE  `json:"CWEs,omitempty"`
}

// CVSS contains the Common Vulnerability Scoring System details.
type CVSS struct {
	VulnImpact   float64 `json:"vuln_impact"`
	Version      string  `json:"version"`
	AttackVector string  `json:"attack_vector"`
}

// CWE define the details of the Common Weakness Enumeration.
type CWE struct {
	ID                   string            `json:"@id"`
	Name                 string            `json:"name"`
	Description          string            `json:"description"`
	BackgroundDetail     string            `json:"background_detail,omitempty"`
	Consequences         []Consequence     `json:"consequences,omitempty"`
	DetectionMethods     []DetectionMethod `json:"detection_methods,omitempty"`
	PotentialMitigations []Mitigation      `json:"potential_mitigations,omitempty"`
	DemostrativeExamples []string          `json:"demostrative_examples,omitempty"`
}

// Consequences enum the scope and impact of the weakness.
type Consequence struct {
	Scope      []string `json:"Scope"`
	Impact     []string `json:"Impact"`
	Note       string   `json:"Note,omitempty"`
	Likelihood string   `json:"Likelihood,omitempty"`
}

// DetectionMethod describe methods for detecting the weakness.
type DetectionMethod struct {
	ID            string `json:"@Detection_Method_ID,omitempty"`
	Method        string `json:"Method"`
	Description   string `json:"Description"`
	Effectiveness string `json:"Effectiveness"`
}

// Mitigation define strategies for mitigating the weakness.
type Mitigation struct {
	Phase              string `json:"Phase"`
	Description        string `json:"Description"`
	Effectiveness      string `json:"Effectiveness"`
	EffectivenessNotes string `json:"Effectiveness_Notes,omitempty"`
}

// ReachableCode describe where the vulnerable code is in the source code.
type ReachableCode struct {
	PathToFile    string     `json:"path_to_file,omitempty"`
	UsedArtifacts []Artifact `json:"used_artifacts,omitempty"`
}

// Artifact represents the details of the artifact.
type Artifact struct {
	ArtifactName string `json:"artifact_name"`
	UsedInLines  []int  `json:"used_in_lines"`
}

// Exploit describe the details of the exploit.
type Exploit struct {
	ID          string `json:"@id,omitempty"`
	Description string `json:"description,omitempty"`
	Payload     string `json:"payload,omitempty"`
}

// ExtendedStatement define the details of the extended statement.
type ExtendedStatement struct {
	AffectedComponent        string            `json:"affected_component"`
	AffectedComponentVersion string            `json:"affected_component_version"`
	AffectedComponentManager string            `json:"affected_component_manager"`
	Vulnerability            Vulnerability     `json:"vulnerability"`
	ReachableCode            []ReachableCode   `json:"recheable_code,omitempty"`
	Exploits                 []Exploit         `json:"exploits,omitempty"`
	Priority                 float64           `json:"priority"`
	Timestamp                *time.Time        `json:"timestamp"`
	LastUpdated              *time.Time        `json:"last_updated"`
	Status                   vex.Status        `json:"status"`
	Justification            vex.Justification `json:"justification"`
}

// ExtendedVEX represents the main document structure.
type ExtendedVEX struct {
	Context            string              `json:"@context"`
	ID                 string              `json:"@id"`
	Author             string              `json:"author"`
	Role               string              `json:"role,omitempty"`
	Timestamp          *time.Time          `json:"timestamp"`
	LastUpdated        string              `json:"last_updated,omitempty"`
	Version            int                 `json:"version"`
	Tooling            string              `json:"tooling,omitempty"`
	ExtendedStatements []ExtendedStatement `json:"extended_statements"`
}
