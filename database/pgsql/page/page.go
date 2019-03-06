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

package page

// Page is the representation of a page for the Postgres schema.
type Page struct {
	// StartID is the ID being used as the basis for pagination across database
	// results. It is used to search for an ancestry with ID >= StartID.
	//
	// StartID is required to be unique to every ancestry and always increasing.
	StartID int64
}
