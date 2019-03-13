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

package util

import (
	"fmt"
	"strings"

	"github.com/lib/pq"
)

func QueryInsert(count int, table string, columns ...string) string {
	base := `INSERT INTO %s (%s) VALUES %s`
	t := pq.QuoteIdentifier(table)
	cols := make([]string, len(columns))
	for i, c := range columns {
		cols[i] = pq.QuoteIdentifier(c)
	}
	colsQuoted := strings.Join(cols, ",")
	return fmt.Sprintf(base, t, colsQuoted, QueryString(len(columns), count))
}

func QueryPersist(count int, table, constraint string, columns ...string) string {
	ct := ""
	if constraint != "" {
		ct = fmt.Sprintf("ON CONSTRAINT %s", constraint)
	}
	return fmt.Sprintf("%s ON CONFLICT %s DO NOTHING", QueryInsert(count, table, columns...), ct)
}

// size of key and array should be both greater than 0
func QueryString(keySize, arraySize int) string {
	if arraySize <= 0 || keySize <= 0 {
		panic("Bulk Query requires size of element tuple and number of elements to be greater than 0")
	}
	keys := make([]string, 0, arraySize)
	for i := 0; i < arraySize; i++ {
		key := make([]string, keySize)
		for j := 0; j < keySize; j++ {
			key[j] = fmt.Sprintf("$%d", i*keySize+j+1)
		}
		keys = append(keys, fmt.Sprintf("(%s)", strings.Join(key, ",")))
	}
	return strings.Join(keys, ",")
}
