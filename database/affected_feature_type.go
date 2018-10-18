// Copyright 2018 clair authors
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

// AffectedFeatureType indicates the type of feature that a vulnerability
// affects.
type AffectedFeatureType string

const (
	// AffectSourcePackage indicates the vulnerability affects a source package.
	AffectSourcePackage AffectedFeatureType = "source"
	// AffectBinaryPackage indicates the vulnerability affects a binary package.
	AffectBinaryPackage AffectedFeatureType = "binary"
)
