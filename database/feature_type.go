// Copyright 2019 clair authors
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
	"database/sql/driver"
	"fmt"
)

// FeatureType indicates the type of feature that a vulnerability
// affects.
type FeatureType string

const (
	SourcePackage FeatureType = "source"
	BinaryPackage FeatureType = "binary"
)

var featureTypes = []FeatureType{
	SourcePackage,
	BinaryPackage,
}

// Scan implements the database/sql.Scanner interface.
func (t *FeatureType) Scan(value interface{}) error {
	val := value.(string)
	for _, ft := range featureTypes {
		if string(ft) == val {
			*t = ft
			return nil
		}
	}

	panic(fmt.Sprintf("invalid feature type received from database: '%s'", val))
}

// Value implements the database/sql/driver.Valuer interface.
func (t *FeatureType) Value() (driver.Value, error) {
	return string(*t), nil
}
