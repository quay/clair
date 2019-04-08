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

package detector

import (
	"database/sql"
	"testing"

	"github.com/deckarep/golang-set"
	"github.com/stretchr/testify/require"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/database/pgsql/testutil"
)

func testGetAllDetectors(tx *sql.Tx) []database.Detector {
	query := `SELECT name, version, dtype FROM detector`
	rows, err := tx.Query(query)
	if err != nil {
		panic(err)
	}

	detectors := []database.Detector{}
	for rows.Next() {
		d := database.Detector{}
		if err := rows.Scan(&d.Name, &d.Version, &d.DType); err != nil {
			panic(err)
		}

		detectors = append(detectors, d)
	}

	return detectors
}

var persistDetectorTests = []struct {
	title string
	in    []database.Detector
	err   string
}{
	{
		title: "invalid detector",
		in: []database.Detector{
			{},
			database.NewFeatureDetector("name", "2.0"),
		},
		err: database.ErrInvalidParameters.Error(),
	},
	{
		title: "invalid detector 2",
		in: []database.Detector{
			database.NewFeatureDetector("name", "2.0"),
			{"name", "1.0", "random not valid dtype"},
		},
		err: database.ErrInvalidParameters.Error(),
	},
	{
		title: "detectors with some different fields",
		in: []database.Detector{
			database.NewFeatureDetector("name", "2.0"),
			database.NewFeatureDetector("name", "1.0"),
			database.NewNamespaceDetector("name", "1.0"),
		},
	},
	{
		title: "duplicated detectors (parameter level)",
		in: []database.Detector{
			database.NewFeatureDetector("name", "1.0"),
			database.NewFeatureDetector("name", "1.0"),
		},
	},
	{
		title: "duplicated detectors (db level)",
		in: []database.Detector{
			database.NewNamespaceDetector("os-release", "1.0"),
			database.NewNamespaceDetector("os-release", "1.0"),
			database.NewFeatureDetector("dpkg", "1.0"),
		},
	},
}

func TestPersistDetector(t *testing.T) {
	tx, cleanup := testutil.CreateTestTxWithFixtures(t, "PersistDetector")
	defer cleanup()

	for _, test := range persistDetectorTests {
		t.Run(test.title, func(t *testing.T) {
			err := PersistDetectors(tx, test.in)
			if test.err != "" {
				require.EqualError(t, err, test.err)
				return
			}

			detectors := testGetAllDetectors(tx)

			// ensure no duplicated detectors
			detectorSet := mapset.NewSet()
			for _, d := range detectors {
				require.False(t, detectorSet.Contains(d), "duplicated: %v", d)
				detectorSet.Add(d)
			}

			// ensure all persisted detectors are actually saved
			for _, d := range test.in {
				require.True(t, detectorSet.Contains(d), "detector: %v, detectors: %v", d, detectorSet)
			}
		})
	}
}
