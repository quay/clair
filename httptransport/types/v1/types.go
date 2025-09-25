// Package types provides concrete types for the HTTP API.
package types

import (
	"embed"
	"encoding/json"
	"fmt"
	"time"
)

//go:embed *.schema.json
var Schema embed.FS

// Indexer types
type (
	Manifest struct {
		Hash   string  `json:"hash"`
		Layers []Layer `json:"layers,omitempty"`
	}

	Layer struct {
		Hash    string              `json:"hash"`
		URI     string              `json:"uri"`
		Headers map[string][]string `json:"headers,omitempty"`
	}

	IndexReport struct {
		Hash          string                    `json:"manifest_hash"`
		State         string                    `json:"state"`
		Err           string                    `json:"err,omitempty"`
		Packages      map[string]*Package       `json:"packages,omitempty"`
		Distributions map[string]*Distribution  `json:"distributions,omitempty"`
		Repositories  map[string]*Repository    `json:"repository,omitempty"`
		Environments  map[string][]*Environment `json:"environments,omitempty"`
		Success       bool                      `json:"success"`
	}

	Package struct {
		ID                string   `json:"id"`
		Name              string   `json:"name,omitempty"`
		Version           string   `json:"version,omitempty"`
		Kind              string   `json:"kind,omitempty"`
		Source            *Package `json:"source,omitempty"`
		NormalizedVersion string   `json:"normalized_version,omitempty"`
		Module            string   `json:"module,omitempty"`
		Arch              string   `json:"arch,omitempty"`
		CPE               string   `json:"cpe,omitempty"`
	}

	Distribution struct {
		ID              string `json:"id"`
		DID             string `json:"did,omitempty"`
		Name            string `json:"name,omitempty"`
		Version         string `json:"version,omitempty"`
		VersionCodeName string `json:"version_code_name,omitempty"`
		VersionID       string `json:"version_id,omitempty"`
		Arch            string `json:"arch,omitempty"`
		CPE             string `json:"cpe,omitempty"`
		PrettyName      string `json:"pretty_name,omitempty"`
	}

	Repository struct {
		ID   string `json:"id,omitempty"`
		Name string `json:"name,omitempty"`
		Key  string `json:"key,omitempty"`
		URI  string `json:"uri,omitempty"`
		CPE  string `json:"cpe,omitempty"`
	}

	Environment struct {
		IntroducedIn   string   `json:"introduced_in"`
		PackageDB      string   `json:"package_db,omitempty"`
		DistributionID string   `json:"distribution_id,omitempty"`
		RepositoryIDs  []string `json:"repository_ids,omitempty"`
	}

	IndexerState struct {
		State string
	}

	VulnerabilityBatch struct {
		Vulnerabilities []Vulnerability
	}
)

// Matcher types
type (
	VulnerabilityReport struct {
		Hash                   string                       `json:"manifest_hash"`
		Packages               map[string]*Package          `json:"packages,omitempty"`
		Vulnerabilities        map[string]*Vulnerability    `json:"vulnerabilities,omitempty"`
		Environments           map[string][]*Environment    `json:"environments,omitempty"`
		PackageVulnerabilities map[string][]string          `json:"package_vulnerabilities,omitempty"`
		Distributions          map[string]*Distribution     `json:"distributions,omitempty"`
		Repositories           map[string]*Repository       `json:"repository,omitempty"`
		Enrichments            map[string][]json.RawMessage `json:"enrichments,omitempty"`
	}

	Vulnerability struct {
		ID                 string        `json:"id"`
		Updater            string        `json:"updater,omitempty"`
		Name               string        `json:"name,omitempty"`
		Issued             time.Time     `json:"issued"`
		Severity           string        `json:"severity,omitempty"`
		NormalizedSeverity string        `json:"normalized_severity,omitempty"`
		Description        string        `json:"description,omitempty"`
		Links              string        `json:"links,omitempty"`
		Package            *Package      `json:"package,omitempty"`
		Dist               *Distribution `json:"distribution,omitempty"`
		Repo               *Repository   `json:"repository,omitempty"`
		FixedInVersion     string        `json:"fixed_in_version"`
		Range              *Range        `json:"range,omitempty"`
		ArchOperation      string        `json:"arch_op,omitempty"`
	}

	Range struct {
		Lower string `json:"[,omitempty"`
		Upper string `json:"),omitempty"`
	}

	UpdateKind int

	UpdateOperation struct {
		Ref         string     `json:"ref"`
		Updater     string     `json:"updater"`
		Fingerprint []byte     `json:"fingerprint"`
		Date        time.Time  `json:"date"`
		Kind        UpdateKind `json:"kind"`
	}

	UpdateDiff struct {
		Prev    UpdateOperation `json:"prev"`
		Cur     UpdateOperation `json:"cur"`
		Added   []Vulnerability `json:"added"`
		Removed []Vulnerability `json:"removed"`
	}
)

//go:generate go run golang.org/x/tools/cmd/stringer@latest -type UpdateKind -linecomment

const (
	_                   UpdateKind = iota
	UpdateVulnerability            // vulnerability
	UpdateEnrichment               // enrichment
)

// API types
type (
	Error struct {
		Code    int
		Message string
	}
)

func (e *Error) Error() string {
	return fmt.Sprintf("%s (HTTP %d)", e.Message, e.Code)
}
