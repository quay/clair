// Copyright 2015 clair authors
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

package database

import (
	"sort"

	"github.com/coreos/clair/utils"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/coreos/clair/utils/types"
	"github.com/google/cayley"
	"github.com/google/cayley/graph"
	"github.com/google/cayley/graph/path"
)

const (
	FieldPackageOS              = "os"
	FieldPackageName            = "name"
	FieldPackageVersion         = "version"
	FieldPackageNextVersion     = "nextVersion"
	FieldPackagePreviousVersion = "previousVersion"

	// This field is not selectable and is for internal use only.
	fieldPackageIsValue = "package"
)

var FieldPackageAll = []string{FieldPackageOS, FieldPackageName, FieldPackageVersion, FieldPackageNextVersion, FieldPackagePreviousVersion}

// Package represents a package
type Package struct {
	Node                string `json:"-"`
	OS                  string
	Name                string
	Version             types.Version
	NextVersionNode     string `json:"-"`
	PreviousVersionNode string `json:"-"`
}

// GetNode returns an unique identifier for the graph node
// Requires the key fields: OS, Name, Version
func (p *Package) GetNode() string {
	return fieldPackageIsValue + ":" + utils.Hash(p.Key())
}

// Key returns an unique string defining p
// Requires the key fields: OS, Name, Version
func (p *Package) Key() string {
	return p.OS + ":" + p.Name + ":" + p.Version.String()
}

// Branch returns an unique string defined the Branch of p (os, name)
// Requires the key fields: OS, Name
func (p *Package) Branch() string {
	return p.OS + ":" + p.Name
}

// AbstractPackage is a package that abstract types.MaxVersion by modifying
// using a AllVersion boolean field and renaming Version to BeforeVersion
// which makes more sense for an usage with a Vulnerability
type AbstractPackage struct {
	OS   string
	Name string

	AllVersions   bool
	BeforeVersion types.Version
}

// PackagesToAbstractPackages converts several Packages to AbstractPackages
func PackagesToAbstractPackages(packages []*Package) (abstractPackages []*AbstractPackage) {
	for _, p := range packages {
		ap := &AbstractPackage{OS: p.OS, Name: p.Name}
		if p.Version != types.MaxVersion {
			ap.BeforeVersion = p.Version
		} else {
			ap.AllVersions = true
		}
		abstractPackages = append(abstractPackages, ap)
	}
	return
}

// AbstractPackagesToPackages converts several AbstractPackages to Packages
func AbstractPackagesToPackages(abstractPackages []*AbstractPackage) (packages []*Package) {
	for _, ap := range abstractPackages {
		p := &Package{OS: ap.OS, Name: ap.Name}
		if ap.AllVersions {
			p.Version = types.MaxVersion
		} else {
			p.Version = ap.BeforeVersion
		}
		packages = append(packages, p)
	}
	return
}

// InsertPackages inserts several packages in the database in one transaction
// Packages are stored in linked lists, one per Branch. Each linked list has a start package and an end package defined with types.MinVersion/types.MaxVersion versions
//
// OS, Name and Version fields have to be specified.
// If the insertion is successfull, the Node field is filled and represents the graph node identifier.
func InsertPackages(packageParameters []*Package) error {
	if len(packageParameters) == 0 {
		return nil
	}

	// Verify parameters
	for _, pkg := range packageParameters {
		if pkg.OS == "" || pkg.Name == "" || pkg.Version.String() == "" {
			log.Warningf("could not insert an incomplete package [OS: %s, Name: %s, Version: %s]", pkg.OS, pkg.Name, pkg.Version)
			return cerrors.NewBadRequestError("could not insert an incomplete package")
		}
	}

	// Iterate over all the packages we need to insert
	for _, packageParameter := range packageParameters {
		t := cayley.NewTransaction()

		// Is the package already existing ?
		pkg, err := FindOnePackage(packageParameter.OS, packageParameter.Name, packageParameter.Version, []string{})
		if err != nil && err != cerrors.ErrNotFound {
			return err
		}
		if pkg != nil {
			packageParameter.Node = pkg.Node
			continue
		}

		// Get all packages of the same branch (both from local cache and database)
		branchPackages, err := FindAllPackagesByBranch(packageParameter.OS, packageParameter.Name, []string{FieldPackageOS, FieldPackageName, FieldPackageVersion, FieldPackageNextVersion})
		if err != nil {
			return err
		}

		if len(branchPackages) == 0 {
			// The branch does not exist yet
			insertingStartPackage := packageParameter.Version == types.MinVersion
			insertingEndPackage := packageParameter.Version == types.MaxVersion

			// Create and insert a end package
			endPackage := &Package{
				OS:      packageParameter.OS,
				Name:    packageParameter.Name,
				Version: types.MaxVersion,
			}
			endPackage.Node = endPackage.GetNode()

			t.AddQuad(cayley.Triple(endPackage.Node, fieldIs, fieldPackageIsValue))
			t.AddQuad(cayley.Triple(endPackage.Node, FieldPackageOS, endPackage.OS))
			t.AddQuad(cayley.Triple(endPackage.Node, FieldPackageName, endPackage.Name))
			t.AddQuad(cayley.Triple(endPackage.Node, FieldPackageVersion, endPackage.Version.String()))
			t.AddQuad(cayley.Triple(endPackage.Node, FieldPackageNextVersion, ""))

			// Create the inserted package if it is different than a start/end package
			var newPackage *Package
			if !insertingStartPackage && !insertingEndPackage {
				newPackage = &Package{
					OS:      packageParameter.OS,
					Name:    packageParameter.Name,
					Version: packageParameter.Version,
				}
				newPackage.Node = newPackage.GetNode()

				t.AddQuad(cayley.Triple(newPackage.Node, fieldIs, fieldPackageIsValue))
				t.AddQuad(cayley.Triple(newPackage.Node, FieldPackageOS, newPackage.OS))
				t.AddQuad(cayley.Triple(newPackage.Node, FieldPackageName, newPackage.Name))
				t.AddQuad(cayley.Triple(newPackage.Node, FieldPackageVersion, newPackage.Version.String()))
				t.AddQuad(cayley.Triple(newPackage.Node, FieldPackageNextVersion, endPackage.Node))

				packageParameter.Node = newPackage.Node
			}

			// Create and insert a start package
			startPackage := &Package{
				OS:      packageParameter.OS,
				Name:    packageParameter.Name,
				Version: types.MinVersion,
			}
			startPackage.Node = startPackage.GetNode()

			t.AddQuad(cayley.Triple(startPackage.Node, fieldIs, fieldPackageIsValue))
			t.AddQuad(cayley.Triple(startPackage.Node, FieldPackageOS, startPackage.OS))
			t.AddQuad(cayley.Triple(startPackage.Node, FieldPackageName, startPackage.Name))
			t.AddQuad(cayley.Triple(startPackage.Node, FieldPackageVersion, startPackage.Version.String()))
			if !insertingStartPackage && !insertingEndPackage {
				t.AddQuad(cayley.Triple(startPackage.Node, FieldPackageNextVersion, newPackage.Node))
			} else {
				t.AddQuad(cayley.Triple(startPackage.Node, FieldPackageNextVersion, endPackage.Node))
			}

			// Set package node
			if insertingEndPackage {
				packageParameter.Node = endPackage.Node
			} else if insertingStartPackage {
				packageParameter.Node = startPackage.Node
			}
		} else {
			// The branch already exists

			// Create the package
			newPackage := &Package{OS: packageParameter.OS, Name: packageParameter.Name, Version: packageParameter.Version}
			newPackage.Node = "package:" + utils.Hash(newPackage.Key())
			packageParameter.Node = newPackage.Node

			t.AddQuad(cayley.Triple(newPackage.Node, fieldIs, fieldPackageIsValue))
			t.AddQuad(cayley.Triple(newPackage.Node, FieldPackageOS, newPackage.OS))
			t.AddQuad(cayley.Triple(newPackage.Node, FieldPackageName, newPackage.Name))
			t.AddQuad(cayley.Triple(newPackage.Node, FieldPackageVersion, newPackage.Version.String()))

			// Sort branchPackages by version (including the new package)
			branchPackages = append(branchPackages, newPackage)
			sort.Sort(ByVersion(branchPackages))

			// Find my prec/succ GraphID in the sorted slice now
			newPackageKey := newPackage.Key()
			var pred, succ *Package
			var found bool
			for _, p := range branchPackages {
				equal := p.Key() == newPackageKey
				if !equal && !found {
					pred = p
				} else if found {
					succ = p
					break
				} else if equal {
					found = true
					continue
				}
			}
			if pred == nil || succ == nil {
				log.Warningf("could not find any package predecessor/successor of: [OS: %s, Name: %s, Version: %s].", packageParameter.OS, packageParameter.Name, packageParameter.Version)
				return cerrors.NewBadRequestError("could not find package predecessor/successor")
			}

			// Link the new packages with the branch
			t.RemoveQuad(cayley.Triple(pred.Node, FieldPackageNextVersion, succ.Node))

			pred.NextVersionNode = newPackage.Node
			t.AddQuad(cayley.Triple(pred.Node, FieldPackageNextVersion, newPackage.Node))

			newPackage.NextVersionNode = succ.Node
			t.AddQuad(cayley.Triple(newPackage.Node, FieldPackageNextVersion, succ.Node))
		}

		// Apply transaction
		if err := store.ApplyTransaction(t); err != nil {
			log.Errorf("failed transaction (InsertPackages): %s", err)
			return ErrTransaction
		}
	}

	// Return
	return nil
}

// FindOnePackage finds and returns a single package having the given OS, name and version, selecting the specified fields
func FindOnePackage(OS, name string, version types.Version, selectedFields []string) (*Package, error) {
	packageParameter := Package{OS: OS, Name: name, Version: version}
	p, err := toPackages(cayley.StartPath(store, packageParameter.GetNode()).Has(fieldIs, fieldPackageIsValue), selectedFields)

	if err != nil {
		return nil, err
	}
	if len(p) == 1 {
		return p[0], nil
	}
	if len(p) > 1 {
		log.Errorf("found multiple packages with identical data [OS: %s, Name: %s, Version: %s]", OS, name, version)
		return nil, ErrInconsistent
	}
	return nil, cerrors.ErrNotFound
}

// FindAllPackagesByNodes finds and returns all packages given by their nodes, selecting the specified fields
func FindAllPackagesByNodes(nodes []string, selectedFields []string) ([]*Package, error) {
	if len(nodes) == 0 {
		return []*Package{}, nil
	}

	return toPackages(cayley.StartPath(store, nodes...).Has(fieldIs, fieldPackageIsValue), selectedFields)
}

// FindAllPackagesByBranch finds and returns all packages that belong to the given Branch, selecting the specified fields
func FindAllPackagesByBranch(OS, name string, selectedFields []string) ([]*Package, error) {
	return toPackages(cayley.StartPath(store, name).In(FieldPackageName).Has(FieldPackageOS, OS), selectedFields)
}

// toPackages converts a path leading to one or multiple packages to Package structs, selecting the specified fields
func toPackages(path *path.Path, selectedFields []string) ([]*Package, error) {
	var packages []*Package
	var err error

	saveFields(path, selectedFields, []string{FieldPackagePreviousVersion})
	it, _ := path.BuildIterator().Optimize()
	defer it.Close()
	for cayley.RawNext(it) {
		tags := make(map[string]graph.Value)
		it.TagResults(tags)

		pkg := Package{Node: store.NameOf(it.Result())}
		for _, selectedField := range selectedFields {
			switch selectedField {
			case FieldPackageOS:
				pkg.OS = store.NameOf(tags[FieldPackageOS])
			case FieldPackageName:
				pkg.Name = store.NameOf(tags[FieldPackageName])
			case FieldPackageVersion:
				pkg.Version, err = types.NewVersion(store.NameOf(tags[FieldPackageVersion]))
				if err != nil {
					log.Warningf("could not parse version of package %s: %s", pkg.Node, err.Error())
				}
			case FieldPackageNextVersion:
				pkg.NextVersionNode = store.NameOf(tags[FieldPackageNextVersion])
			case FieldPackagePreviousVersion:
				pkg.PreviousVersionNode, err = toValue(cayley.StartPath(store, pkg.Node).In(FieldPackageNextVersion))
				if err != nil {
					log.Warningf("could not get previousVersion on package %s: %s.", pkg.Node, err.Error())
					return []*Package{}, ErrInconsistent
				}
			default:
				panic("unknown selectedField")
			}
		}
		packages = append(packages, &pkg)
	}
	if it.Err() != nil {
		log.Errorf("failed query in toPackages: %s", it.Err())
		return []*Package{}, ErrBackendException
	}

	return packages, nil
}

// NextVersion find and returns the package of the same branch that has a higher version number, selecting the specified fields
// It requires that FieldPackageNextVersion field has been selected on p
func (p *Package) NextVersion(selectedFields []string) (*Package, error) {
	if p.NextVersionNode == "" {
		return nil, nil
	}

	v, err := FindAllPackagesByNodes([]string{p.NextVersionNode}, selectedFields)
	if err != nil {
		return nil, err
	}
	if len(v) != 1 {
		log.Errorf("found multiple packages when getting next version of package %s", p.Node)
		return nil, ErrInconsistent
	}
	return v[0], nil
}

// NextVersions find and returns all the packages of the same branch that have
// a higher version number, selecting the specified fields
// It requires that FieldPackageNextVersion field has been selected on p
// The immediate higher version is listed first, and the special end-of-Branch package is last, p is not listed
func (p *Package) NextVersions(selectedFields []string) ([]*Package, error) {
	var nextVersions []*Package

	if !utils.Contains(FieldPackageNextVersion, selectedFields) {
		selectedFields = append(selectedFields, FieldPackageNextVersion)
	}

	nextVersion, err := p.NextVersion(selectedFields)
	if err != nil {
		return []*Package{}, err
	}
	if nextVersion != nil {
		nextVersions = append(nextVersions, nextVersion)

		nextNextVersions, err := nextVersion.NextVersions(selectedFields)
		if err != nil {
			return []*Package{}, err
		}
		nextVersions = append(nextVersions, nextNextVersions...)
	}

	return nextVersions, nil
}

// PreviousVersion find and returns the package of the same branch that has an
// immediate lower version number, selecting the specified fields
// It requires that FieldPackagePreviousVersion field has been selected on p
func (p *Package) PreviousVersion(selectedFields []string) (*Package, error) {
	if p.PreviousVersionNode == "" {
		return nil, nil
	}

	v, err := FindAllPackagesByNodes([]string{p.PreviousVersionNode}, selectedFields)
	if err != nil {
		return nil, err
	}
	if len(v) == 0 {
		return nil, nil
	}
	if len(v) != 1 {
		log.Errorf("found multiple packages when getting previous version of package %s", p.Node)
		return nil, ErrInconsistent
	}
	return v[0], nil
}

// PreviousVersions find and returns all the packages of the same branch that
// have a lower version number, selecting the specified fields
// It requires that FieldPackageNextVersion field has been selected on p
// The immediate lower version is listed first, and the special start-of-Branch
// package is last, p is not listed
func (p *Package) PreviousVersions(selectedFields []string) ([]*Package, error) {
	var previousVersions []*Package

	if !utils.Contains(FieldPackagePreviousVersion, selectedFields) {
		selectedFields = append(selectedFields, FieldPackagePreviousVersion)
	}

	previousVersion, err := p.PreviousVersion(selectedFields)
	if err != nil {
		return []*Package{}, err
	}
	if previousVersion != nil {
		previousVersions = append(previousVersions, previousVersion)

		previousPreviousVersions, err := previousVersion.PreviousVersions(selectedFields)
		if err != nil {
			return []*Package{}, err
		}
		previousVersions = append(previousVersions, previousPreviousVersions...)
	}

	return previousVersions, nil
}

// ByVersion implements sort.Interface for []*Package based on the Version field
// It uses github.com/quentin-m/dpkgcomp internally and makes use of types.MinVersion/types.MaxVersion
type ByVersion []*Package

func (p ByVersion) Len() int           { return len(p) }
func (p ByVersion) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p ByVersion) Less(i, j int) bool { return p[i].Version.Compare(p[j].Version) < 0 }
