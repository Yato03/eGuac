// Code generated by ent, DO NOT EDIT.

package certifyvex

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/google/uuid"
)

const (
	// Label holds the string label denoting the certifyvex type in the database.
	Label = "certify_vex"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldPackageID holds the string denoting the package_id field in the database.
	FieldPackageID = "package_id"
	// FieldArtifactID holds the string denoting the artifact_id field in the database.
	FieldArtifactID = "artifact_id"
	// FieldVulnerabilityID holds the string denoting the vulnerability_id field in the database.
	FieldVulnerabilityID = "vulnerability_id"
	// FieldKnownSince holds the string denoting the known_since field in the database.
	FieldKnownSince = "known_since"
	// FieldStatus holds the string denoting the status field in the database.
	FieldStatus = "status"
	// FieldStatement holds the string denoting the statement field in the database.
	FieldStatement = "statement"
	// FieldStatusNotes holds the string denoting the status_notes field in the database.
	FieldStatusNotes = "status_notes"
	// FieldJustification holds the string denoting the justification field in the database.
	FieldJustification = "justification"
	// FieldOrigin holds the string denoting the origin field in the database.
	FieldOrigin = "origin"
	// FieldCollector holds the string denoting the collector field in the database.
	FieldCollector = "collector"
	// FieldDocumentRef holds the string denoting the document_ref field in the database.
	FieldDocumentRef = "document_ref"
	// FieldDescription holds the string denoting the description field in the database.
	FieldDescription = "description"
	// FieldPriority holds the string denoting the priority field in the database.
	FieldPriority = "priority"
	// EdgePackage holds the string denoting the package edge name in mutations.
	EdgePackage = "package"
	// EdgeArtifact holds the string denoting the artifact edge name in mutations.
	EdgeArtifact = "artifact"
	// EdgeVulnerability holds the string denoting the vulnerability edge name in mutations.
	EdgeVulnerability = "vulnerability"
	// EdgeCvss holds the string denoting the cvss edge name in mutations.
	EdgeCvss = "cvss"
	// EdgeCwe holds the string denoting the cwe edge name in mutations.
	EdgeCwe = "cwe"
	// EdgeExploit holds the string denoting the exploit edge name in mutations.
	EdgeExploit = "exploit"
	// EdgeReachableCode holds the string denoting the reachable_code edge name in mutations.
	EdgeReachableCode = "reachable_code"
	// Table holds the table name of the certifyvex in the database.
	Table = "certify_vexes"
	// PackageTable is the table that holds the package relation/edge.
	PackageTable = "certify_vexes"
	// PackageInverseTable is the table name for the PackageVersion entity.
	// It exists in this package in order to avoid circular dependency with the "packageversion" package.
	PackageInverseTable = "package_versions"
	// PackageColumn is the table column denoting the package relation/edge.
	PackageColumn = "package_id"
	// ArtifactTable is the table that holds the artifact relation/edge.
	ArtifactTable = "certify_vexes"
	// ArtifactInverseTable is the table name for the Artifact entity.
	// It exists in this package in order to avoid circular dependency with the "artifact" package.
	ArtifactInverseTable = "artifacts"
	// ArtifactColumn is the table column denoting the artifact relation/edge.
	ArtifactColumn = "artifact_id"
	// VulnerabilityTable is the table that holds the vulnerability relation/edge.
	VulnerabilityTable = "certify_vexes"
	// VulnerabilityInverseTable is the table name for the VulnerabilityID entity.
	// It exists in this package in order to avoid circular dependency with the "vulnerabilityid" package.
	VulnerabilityInverseTable = "vulnerability_ids"
	// VulnerabilityColumn is the table column denoting the vulnerability relation/edge.
	VulnerabilityColumn = "vulnerability_id"
	// CvssTable is the table that holds the cvss relation/edge.
	CvssTable = "certify_vexes"
	// CvssInverseTable is the table name for the CVSS entity.
	// It exists in this package in order to avoid circular dependency with the "cvss" package.
	CvssInverseTable = "cvs_ss"
	// CvssColumn is the table column denoting the cvss relation/edge.
	CvssColumn = "certify_vex_cvss"
	// CweTable is the table that holds the cwe relation/edge. The primary key declared below.
	CweTable = "certify_vex_cwe"
	// CweInverseTable is the table name for the CWE entity.
	// It exists in this package in order to avoid circular dependency with the "cwe" package.
	CweInverseTable = "cw_es"
	// ExploitTable is the table that holds the exploit relation/edge. The primary key declared below.
	ExploitTable = "certify_vex_exploit"
	// ExploitInverseTable is the table name for the Exploit entity.
	// It exists in this package in order to avoid circular dependency with the "exploit" package.
	ExploitInverseTable = "exploits"
	// ReachableCodeTable is the table that holds the reachable_code relation/edge. The primary key declared below.
	ReachableCodeTable = "certify_vex_reachable_code"
	// ReachableCodeInverseTable is the table name for the ReachableCode entity.
	// It exists in this package in order to avoid circular dependency with the "reachablecode" package.
	ReachableCodeInverseTable = "reachable_codes"
)

// Columns holds all SQL columns for certifyvex fields.
var Columns = []string{
	FieldID,
	FieldPackageID,
	FieldArtifactID,
	FieldVulnerabilityID,
	FieldKnownSince,
	FieldStatus,
	FieldStatement,
	FieldStatusNotes,
	FieldJustification,
	FieldOrigin,
	FieldCollector,
	FieldDocumentRef,
	FieldDescription,
	FieldPriority,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "certify_vexes"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"certify_vex_cvss",
}

var (
	// CwePrimaryKey and CweColumn2 are the table columns denoting the
	// primary key for the cwe relation (M2M).
	CwePrimaryKey = []string{"certify_vex_id", "cwe_id"}
	// ExploitPrimaryKey and ExploitColumn2 are the table columns denoting the
	// primary key for the exploit relation (M2M).
	ExploitPrimaryKey = []string{"certify_vex_id", "exploit_id"}
	// ReachableCodePrimaryKey and ReachableCodeColumn2 are the table columns denoting the
	// primary key for the reachable_code relation (M2M).
	ReachableCodePrimaryKey = []string{"certify_vex_id", "reachable_code_id"}
)

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	for i := range ForeignKeys {
		if column == ForeignKeys[i] {
			return true
		}
	}
	return false
}

var (
	// DefaultID holds the default value on creation for the "id" field.
	DefaultID func() uuid.UUID
)

// OrderOption defines the ordering options for the CertifyVex queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByPackageID orders the results by the package_id field.
func ByPackageID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldPackageID, opts...).ToFunc()
}

// ByArtifactID orders the results by the artifact_id field.
func ByArtifactID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldArtifactID, opts...).ToFunc()
}

// ByVulnerabilityID orders the results by the vulnerability_id field.
func ByVulnerabilityID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldVulnerabilityID, opts...).ToFunc()
}

// ByKnownSince orders the results by the known_since field.
func ByKnownSince(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldKnownSince, opts...).ToFunc()
}

// ByStatus orders the results by the status field.
func ByStatus(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldStatus, opts...).ToFunc()
}

// ByStatement orders the results by the statement field.
func ByStatement(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldStatement, opts...).ToFunc()
}

// ByStatusNotes orders the results by the status_notes field.
func ByStatusNotes(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldStatusNotes, opts...).ToFunc()
}

// ByJustification orders the results by the justification field.
func ByJustification(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldJustification, opts...).ToFunc()
}

// ByOrigin orders the results by the origin field.
func ByOrigin(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldOrigin, opts...).ToFunc()
}

// ByCollector orders the results by the collector field.
func ByCollector(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldCollector, opts...).ToFunc()
}

// ByDocumentRef orders the results by the document_ref field.
func ByDocumentRef(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldDocumentRef, opts...).ToFunc()
}

// ByDescription orders the results by the description field.
func ByDescription(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldDescription, opts...).ToFunc()
}

// ByPriority orders the results by the priority field.
func ByPriority(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldPriority, opts...).ToFunc()
}

// ByPackageField orders the results by package field.
func ByPackageField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newPackageStep(), sql.OrderByField(field, opts...))
	}
}

// ByArtifactField orders the results by artifact field.
func ByArtifactField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newArtifactStep(), sql.OrderByField(field, opts...))
	}
}

// ByVulnerabilityField orders the results by vulnerability field.
func ByVulnerabilityField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newVulnerabilityStep(), sql.OrderByField(field, opts...))
	}
}

// ByCvssField orders the results by cvss field.
func ByCvssField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newCvssStep(), sql.OrderByField(field, opts...))
	}
}

// ByCweCount orders the results by cwe count.
func ByCweCount(opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborsCount(s, newCweStep(), opts...)
	}
}

// ByCwe orders the results by cwe terms.
func ByCwe(term sql.OrderTerm, terms ...sql.OrderTerm) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newCweStep(), append([]sql.OrderTerm{term}, terms...)...)
	}
}

// ByExploitCount orders the results by exploit count.
func ByExploitCount(opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborsCount(s, newExploitStep(), opts...)
	}
}

// ByExploit orders the results by exploit terms.
func ByExploit(term sql.OrderTerm, terms ...sql.OrderTerm) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newExploitStep(), append([]sql.OrderTerm{term}, terms...)...)
	}
}

// ByReachableCodeCount orders the results by reachable_code count.
func ByReachableCodeCount(opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborsCount(s, newReachableCodeStep(), opts...)
	}
}

// ByReachableCode orders the results by reachable_code terms.
func ByReachableCode(term sql.OrderTerm, terms ...sql.OrderTerm) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newReachableCodeStep(), append([]sql.OrderTerm{term}, terms...)...)
	}
}
func newPackageStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(PackageInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, false, PackageTable, PackageColumn),
	)
}
func newArtifactStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(ArtifactInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, false, ArtifactTable, ArtifactColumn),
	)
}
func newVulnerabilityStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(VulnerabilityInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, false, VulnerabilityTable, VulnerabilityColumn),
	)
}
func newCvssStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(CvssInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, false, CvssTable, CvssColumn),
	)
}
func newCweStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(CweInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2M, false, CweTable, CwePrimaryKey...),
	)
}
func newExploitStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(ExploitInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2M, false, ExploitTable, ExploitPrimaryKey...),
	)
}
func newReachableCodeStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(ReachableCodeInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2M, false, ReachableCodeTable, ReachableCodePrimaryKey...),
	)
}
