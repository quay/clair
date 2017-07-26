// Copyright 2016 clair authors
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

package migrations

import "github.com/remind101/migrate"

func init() {
	RegisterMigration(migrate.Migration{
		ID: 1,
		Up: migrate.Queries([]string{
			// namespaces
			`CREATE TABLE IF NOT EXISTS namespace (
		id SERIAL PRIMARY KEY,
		name TEXT NULL,
		version_format TEXT,
		UNIQUE (name, version_format));`,
			`CREATE INDEX ON namespace(name);`,

			// features
			`CREATE TABLE IF NOT EXISTS feature (
		id SERIAL PRIMARY KEY,
		name TEXT NOT NULL,
		version TEXT NOT NULL,
		version_format TEXT NOT NULL,
		UNIQUE (name, version, version_format));`,
			`CREATE INDEX ON feature(name);`,

			`CREATE TABLE IF NOT EXISTS namespaced_feature (
		id SERIAL PRIMARY KEY,
		namespace_id INT REFERENCES namespace,
		feature_id INT REFERENCES feature,
		UNIQUE (namespace_id, feature_id));`,

			// layers
			`CREATE TABLE IF NOT EXISTS layer(
		id SERIAL PRIMARY KEY, 
		hash TEXT NOT NULL UNIQUE);`,

			`CREATE TABLE IF NOT EXISTS layer_feature (
		id SERIAL PRIMARY KEY, 
		layer_id INT REFERENCES layer ON DELETE CASCADE, 
		feature_id INT REFERENCES feature ON DELETE CASCADE,
		UNIQUE (layer_id, feature_id));`,
			`CREATE INDEX ON layer_feature(layer_id);`,

			`CREATE TABLE IF NOT EXISTS layer_lister (
		id SERIAL PRIMARY KEY, 
		layer_id INT REFERENCES layer ON DELETE CASCADE,
		lister TEXT NOT NULL,
		UNIQUE (layer_id, lister));`,
			`CREATE INDEX ON layer_lister(layer_id);`,

			`CREATE TABLE IF NOT EXISTS layer_detector (
		id SERIAL PRIMARY KEY, 
		layer_id INT REFERENCES layer ON DELETE CASCADE,
		detector TEXT,
		UNIQUE (layer_id, detector));`,
			`CREATE INDEX ON layer_detector(layer_id);`,

			`CREATE TABLE IF NOT EXISTS layer_namespace (
		id SERIAL PRIMARY KEY, 
		layer_id INT REFERENCES layer ON DELETE CASCADE,
		namespace_id INT REFERENCES namespace ON DELETE CASCADE,
		UNIQUE (layer_id, namespace_id));`,
			`CREATE INDEX ON layer_namespace(layer_id);`,

			// ancestry
			`CREATE TABLE IF NOT EXISTS ancestry (
		id SERIAL PRIMARY KEY,
		name TEXT NOT NULL UNIQUE);`,

			`CREATE TABLE IF NOT EXISTS ancestry_layer (
		id SERIAL PRIMARY KEY,
		ancestry_id INT REFERENCES ancestry ON DELETE CASCADE,
		ancestry_index INT NOT NULL,
		layer_id INT REFERENCES layer ON DELETE RESTRICT,
		UNIQUE (ancestry_id, ancestry_index));`,
			`CREATE INDEX ON ancestry_layer(ancestry_id);`,

			`CREATE TABLE IF NOT EXISTS ancestry_feature (
		id SERIAL PRIMARY KEY, 
		ancestry_id INT REFERENCES ancestry ON DELETE CASCADE, 
		namespaced_feature_id INT REFERENCES namespaced_feature ON DELETE CASCADE,
		UNIQUE (ancestry_id, namespaced_feature_id));`,

			`CREATE TABLE IF NOT EXISTS ancestry_lister (
		id SERIAL PRIMARY KEY,
		ancestry_id INT REFERENCES ancestry ON DELETE CASCADE,
		lister TEXT,
		UNIQUE (ancestry_id, lister));`,
			`CREATE INDEX ON ancestry_lister(ancestry_id);`,

			`CREATE TABLE IF NOT EXISTS ancestry_detector (
		id SERIAL PRIMARY KEY,
		ancestry_id INT REFERENCES ancestry ON DELETE CASCADE,
		detector TEXT,
		UNIQUE (ancestry_id, detector));`,
			`CREATE INDEX ON ancestry_detector(ancestry_id);`,

			`CREATE TYPE severity AS ENUM ('Unknown', 'Negligible', 'Low', 'Medium', 'High', 'Critical', 'Defcon1');`,

			// vulnerability
			`CREATE TABLE IF NOT EXISTS vulnerability (
		id SERIAL PRIMARY KEY,
		namespace_id INT NOT NULL REFERENCES Namespace,
		name TEXT NOT NULL,
		description TEXT NULL,
		link TEXT NULL,
		severity severity NOT NULL,
		metadata TEXT NULL,
		created_at TIMESTAMP WITH TIME ZONE,
		deleted_at TIMESTAMP WITH TIME ZONE NULL);`,
			`CREATE INDEX ON vulnerability(namespace_id, name);`,
			`CREATE INDEX ON vulnerability(namespace_id);`,

			`CREATE TABLE IF NOT EXISTS vulnerability_affected_feature (
		id SERIAL PRIMARY KEY, 
		vulnerability_id INT NOT NULL REFERENCES vulnerability ON DELETE CASCADE,
		feature_name TEXT NOT NULL,
		affected_version TEXT,
		fixedin TEXT);`,
			`CREATE INDEX ON vulnerability_affected_feature(vulnerability_id, feature_name);`,

			`CREATE TABLE IF NOT EXISTS vulnerability_affected_namespaced_feature(
		id SERIAL PRIMARY KEY,
		vulnerability_id INT NOT NULL REFERENCES vulnerability ON DELETE CASCADE,
		namespaced_feature_id INT NOT NULL REFERENCES namespaced_feature ON DELETE CASCADE,
		added_by INT NOT NULL REFERENCES vulnerability_affected_feature ON DELETE CASCADE,
		UNIQUE (vulnerability_id, namespaced_feature_id));`,
			`CREATE INDEX ON vulnerability_affected_namespaced_feature(namespaced_feature_id);`,

			`CREATE TABLE IF NOT EXISTS KeyValue (
		id SERIAL PRIMARY KEY,
		key TEXT NOT NULL UNIQUE,
		value TEXT);`,

			`CREATE TABLE IF NOT EXISTS Lock (
		id SERIAL PRIMARY KEY,
		name VARCHAR(64) NOT NULL UNIQUE,
		owner VARCHAR(64) NOT NULL,
		until TIMESTAMP WITH TIME ZONE);`,
			`CREATE INDEX ON Lock (owner);`,

			// Notification
			`CREATE TABLE IF NOT EXISTS Vulnerability_Notification (
		id SERIAL PRIMARY KEY,
		name VARCHAR(64) NOT NULL UNIQUE,
		created_at TIMESTAMP WITH TIME ZONE,
		notified_at TIMESTAMP WITH TIME ZONE NULL,
		deleted_at TIMESTAMP WITH TIME ZONE NULL,
		old_vulnerability_id INT NULL REFERENCES Vulnerability ON DELETE CASCADE,
		new_vulnerability_id INT NULL REFERENCES Vulnerability ON DELETE CASCADE);`,
			`CREATE INDEX ON Vulnerability_Notification (notified_at);`,
		}),
		Down: migrate.Queries([]string{
			`DROP TABLE IF EXISTS
		ancestry,
		ancestry_layer,
		ancestry_feature,
		ancestry_detector,
		ancestry_lister,
		feature,
		namespaced_feature,
		keyvalue,
		layer,
		layer_detector,
		layer_feature,
		layer_lister,
		layer_namespace,
		lock,
		namespace,
		vulnerability,
		vulnerability_affected_feature,
		vulnerability_affected_namespaced_feature,
		vulnerability_notification
		CASCADE;`,
			`DROP TYPE IF EXISTS severity;`,
		}),
	})
}
