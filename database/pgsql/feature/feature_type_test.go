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

package feature

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/database/pgsql/testutil"
)

func TestGetFeatureTypeMap(t *testing.T) {
	tx, cleanup := testutil.CreateTestTx(t, "TestGetFeatureTypeMap")
	defer cleanup()

	types, err := GetFeatureTypeMap(tx)
	if err != nil {
		require.Nil(t, err, err.Error())
	}

	require.Equal(t, database.SourcePackage, types.ByID[1])
	require.Equal(t, database.BinaryPackage, types.ByID[2])
	require.Equal(t, 1, types.ByName[database.SourcePackage])
	require.Equal(t, 2, types.ByName[database.BinaryPackage])
}
