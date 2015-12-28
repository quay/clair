package database

import "github.com/coreos/clair/utils/types"

type Model struct {
	ID int
}

type Layer struct {
	Model

	Name          string
	EngineVersion int
	Parent        *Layer
	Namespace     *Namespace
	Features      []FeatureVersion
}

type Namespace struct {
	Model

	Name string
}

type Feature struct {
	Model

	Name      string
	Namespace Namespace
	// FixedBy   map[types.Version]Vulnerability // <<-- WRONG.
}

type FeatureVersion struct {
	Model

	Feature    Feature
	Version    types.Version
	AffectedBy []Vulnerability
}

type Vulnerability struct {
	Model

	Name        string
	Namespace   Namespace
	Description string
	Link        string
	Severity    types.Priority
	// FixedIn     map[types.Version]Feature // <<-- WRONG.
	Affects []FeatureVersion

	// For output purposes. Only make sense when the vulnerability
	// is already about a specific Feature/FeatureVersion.
	FixedBy types.Version
}
