// Copyright 2017 clair authors
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

package database_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coreos/clair/database"
)

func TestParseDetectorType(t *testing.T) {
	_, err := database.NewDetectorType("")
	require.Equal(t, database.ErrFailedToParseDetectorType, err)

	_, err = database.NewDetectorType("∞")
	require.Equal(t, database.ErrFailedToParseDetectorType, err)

	for _, dtype := range database.DetectorTypes {
		dtypeNew, err := database.NewDetectorType(string(dtype))
		require.Nil(t, err)
		require.Equal(t, dtype, dtypeNew)
	}
}
