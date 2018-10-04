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

	"github.com/stretchr/testify/assert"

	"github.com/coreos/clair/database"
)

func TestCompareSeverity(t *testing.T) {
	assert.Equal(t, database.MediumSeverity.Compare(database.MediumSeverity), 0, "Severity comparison failed")
	assert.True(t, database.MediumSeverity.Compare(database.HighSeverity) < 0, "Severity comparison failed")
	assert.True(t, database.CriticalSeverity.Compare(database.LowSeverity) > 0, "Severity comparison failed")
}

func TestParseSeverity(t *testing.T) {
	_, err := database.NewSeverity("Test")
	assert.Equal(t, database.ErrFailedToParseSeverity, err)

	_, err = database.NewSeverity("Unknown")
	assert.Nil(t, err)
}
