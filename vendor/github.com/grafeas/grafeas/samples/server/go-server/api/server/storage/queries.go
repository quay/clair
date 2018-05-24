// Copyright 2017 The Grafeas Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package storage

const (
	createTables = `
		CREATE TABLE IF NOT EXISTS projects (
			id SERIAL PRIMARY KEY,
			name TEXT NOT NULL UNIQUE
		);
		CREATE TABLE IF NOT EXISTS notes (
			id SERIAL PRIMARY KEY,
			project_name TEXT NOT NULL,
			note_name TEXT NOT NULL,
			data TEXT,
			UNIQUE (project_name, note_name)
		);
		CREATE TABLE IF NOT EXISTS occurrences (
			id SERIAL PRIMARY KEY,
			project_name TEXT NOT NULL,
			occurrence_name TEXT NOT NULL,
			data TEXT,
			note_id int REFERENCES notes NOT NULL,
			UNIQUE (project_name, occurrence_name)
		);
		CREATE TABLE IF NOT EXISTS operations (
			id SERIAL PRIMARY KEY,
			project_name TEXT NOT NULL,
			operation_name TEXT NOT NULL,
			data TEXT,
			UNIQUE (project_name, operation_name)
		);`

	insertProject = `INSERT INTO projects(name) VALUES ($1)`
	projectExists = `SELECT EXISTS (SELECT 1 FROM projects WHERE name = $1)`
	deleteProject = `DELETE FROM projects WHERE name = $1`
	listProjects  = `SELECT id, name FROM projects WHERE id > $2 LIMIT $1`

	insertOccurrence = `INSERT INTO occurrences(project_name, occurrence_name, note_id, data)
                      VALUES ($1, $2, (SELECT id FROM notes WHERE project_name = $3 AND note_name = $4), $5)`
	searchOccurrence = `SELECT data FROM occurrences WHERE project_name = $1 AND occurrence_name = $2`
	updateOccurrence = `UPDATE occurrences SET data = $3 WHERE project_name = $1 AND occurrence_name = $2`
	deleteOccurrence = `DELETE FROM occurrences WHERE project_name = $1 AND occurrence_name = $2`
	listOccurrences  = `SELECT id, data FROM occurrences WHERE project_name = $1 AND id > $3 LIMIT $2`

	insertNote          = `INSERT INTO notes(project_name, note_name, data) VALUES ($1, $2, $3)`
	searchNote          = `SELECT data FROM notes WHERE project_name = $1 AND note_name = $2`
	updateNote          = `UPDATE notes SET data = $3 WHERE project_name = $1 AND note_name = $2`
	deleteNote          = `DELETE FROM notes WHERE project_name = $1 AND note_name = $2`
	listNotes           = `SELECT id, data FROM notes WHERE project_name = $1 AND id > $3 LIMIT $2`
	listNoteOccurrences = `SELECT o.id, o.data FROM occurrences as o, notes as n
	                         WHERE n.id = o.note_id
	                           AND n.project_name = $1
	                           AND n.note_name = $2
	                           AND o.id > $4
	                           LIMIT $3`

	insertOperation = `INSERT INTO operations(project_name, operation_name, data) VALUES ($1, $2, $3)`
	searchOperation = `SELECT data FROM operations WHERE project_name = $1 AND operation_name = $2`
	deleteOperation = `DELETE FROM operations WHERE project_name = $1 AND operation_name = $2`
	updateOperation = `UPDATE operations SET data = $3 WHERE project_name = $1 AND operation_name = $2`
	listOperations  = `SELECT id, data FROM operations WHERE project_name = $1 AND id > $3 LIMIT $2`
)
