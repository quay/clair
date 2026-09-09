// Package keys contains a common set of JSON keys used in the v1 API types.
//
// Some are used in multiple contexts. This package is simply a registry of the
// values and does not try to add information about the "correct" context.
package keys

// All the object keys used throughout the HTTP API types.
const (
	Arch                   = `arch`
	ArchOp                 = `arch_op`
	CPE                    = `cpe`
	Description            = `description`
	DID                    = `did`
	Distribution           = `distribution`
	DistributionID         = `distribution_id`
	Distributions          = `distributions`
	Enrichments            = `enrichments`
	Environments           = `environments`
	Err                    = `err`
	FixedIn                = `fixed_in_version`
	Hash                   = `hash`
	Headers                = `headers`
	ID                     = `id`
	Introduced             = `introduced_in`
	Issued                 = `issued`
	Key                    = `key`
	Kind                   = `kind`
	Layers                 = `layers`
	Links                  = `links`
	Module                 = `module`
	Name                   = `name`
	NormSeverity           = `normalized_severity`
	NormVersion            = `normalized_version`
	PackageDB              = `package_db`
	Package                = `package`
	Packages               = `packages`
	PackageVulnerabilities = `package_vulnerabilities`
	PrettyName             = `pretty_name`
	RangeLower             = `[`
	Range                  = `range`
	RangeUpper             = `)`
	ReportHash             = `manifest_hash`
	RepositoryIDs          = `repository_ids`
	Repository             = `repository`
	Severity               = `severity`
	Source                 = `source`
	State                  = `state`
	Success                = `success`
	Updater                = `updater`
	URI                    = `uri`
	VersionCodeName        = `version_code_name`
	VersionID              = `version_id`
	Version                = `version`
	Vulnerabilities        = `vulnerabilities`
)
