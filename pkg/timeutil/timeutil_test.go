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

package timeutil

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestExpBackoff(t *testing.T) {
	prev := 5 * time.Second
	max := 8 * time.Second
	assert.Equal(t, time.Second, ExpBackoff(prev, 0))
	assert.Equal(t, time.Second, ExpBackoff(0, max))
	assert.Equal(t, max, ExpBackoff(prev, max))
	assert.Equal(t, 2*prev, ExpBackoff(prev, time.Hour))
}
