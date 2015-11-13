// Copyright 2015 quay-sec authors
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

import cerrors "github.com/coreos/quay-sec/utils/errors"

// FindAllLayersIntroducingVulnerability finds and returns the list of layers
// that introduce the given vulnerability (by its ID), selecting the specified fields
func FindAllLayersIntroducingVulnerability(vulnerabilityID string, selectedFields []string) ([]*Layer, error) {
	// Find vulnerability
	vulnerability, err := FindOneVulnerability(vulnerabilityID, []string{FieldVulnerabilityFixedIn})
	if err != nil {
		return []*Layer{}, err
	}
	if vulnerability == nil {
		return []*Layer{}, cerrors.ErrNotFound
	}

	// Find FixedIn packages
	fixedInPackages, err := FindAllPackagesByNodes(vulnerability.FixedInNodes, []string{FieldPackagePreviousVersion})
	if err != nil {
		return []*Layer{}, err
	}

	// Find all FixedIn packages's ancestors packages (which are therefore vulnerable to the vulnerability)
	var vulnerablePackagesNodes []string
	for _, pkg := range fixedInPackages {
		previousVersions, err := pkg.PreviousVersions([]string{})
		if err != nil {
			return []*Layer{}, err
		}
		for _, version := range previousVersions {
			vulnerablePackagesNodes = append(vulnerablePackagesNodes, version.Node)
		}
	}

	// Return all the layers that add these packages
	return FindAllLayersByAddedPackageNodes(vulnerablePackagesNodes, selectedFields)
}
