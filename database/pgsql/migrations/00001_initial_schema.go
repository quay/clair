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

var (
	// entities are the basic building blocks to relate the vulnerabilities with
	// the ancestry.
	entities = MigrationQuery{
		Up: []string{
			`CREATE TABLE IF NOT EXISTS feature_type (
				id SERIAL PRIMARY KEY,
				name TEXT NOT NULL UNIQUE);`,

			`INSERT INTO feature_type(name) VALUES ('source'), ('binary')`,

			`CREATE TABLE IF NOT EXISTS namespace (
				id SERIAL PRIMARY KEY,
				name TEXT NULL,
				version_format TEXT,
				UNIQUE (name, version_format));`,
			`CREATE INDEX ON namespace(name);`,

			`CREATE TABLE IF NOT EXISTS feature (
				id SERIAL PRIMARY KEY,
				name TEXT NOT NULL,
				version TEXT NOT NULL,
				version_format TEXT NOT NULL,
				type INT REFERENCES feature_type ON DELETE CASCADE,
				UNIQUE (name, version, version_format, type));`,
			`CREATE INDEX ON feature(name);`,

			`CREATE TABLE IF NOT EXISTS namespaced_feature (
				id SERIAL PRIMARY KEY,
				namespace_id INT REFERENCES namespace ON DELETE CASCADE,
				feature_id INT REFERENCES feature ON DELETE CASCADE,
				UNIQUE (namespace_id, feature_id));`,
		},
		Down: []string{
			`DROP TABLE IF EXISTS namespace, feature, namespaced_feature, feature_type CASCADE;`,
		},
	}

	// detector is analysis extensions used by the worker.
	detector = MigrationQuery{
		Up: []string{
			`CREATE TYPE detector_type AS ENUM ('namespace', 'feature');`,

			`CREATE TABLE IF NOT EXISTS detector (
				id SERIAL PRIMARY KEY,
				name TEXT NOT NULL,
				version TEXT NOT NULL,
				dtype detector_type NOT NULL,
				UNIQUE (name, version, dtype));`,
		},
		Down: []string{
			`DROP TABLE IF EXISTS detector CASCADE;`,
			`DROP TYPE IF EXISTS detector_type;`,
		},
	}

	// layer contains all metadata and scanned features and namespaces.
	layer = MigrationQuery{
		Up: []string{
			`CREATE TABLE IF NOT EXISTS layer(
				id SERIAL PRIMARY KEY,
				hash TEXT NOT NULL UNIQUE);`,

			`CREATE TABLE IF NOT EXISTS layer_detector(
				id SERIAL PRIMARY KEY,
				layer_id INT REFERENCES layer ON DELETE CASCADE,
				detector_id INT REFERENCES detector ON DELETE CASCADE,
				UNIQUE(layer_id, detector_id));`,
			`CREATE INDEX ON layer_detector(layer_id);`,

			`CREATE TABLE IF NOT EXISTS layer_feature (
				id SERIAL PRIMARY KEY,
				layer_id INT REFERENCES layer ON DELETE CASCADE, 
				feature_id INT REFERENCES feature ON DELETE CASCADE,
				detector_id INT REFERENCES detector ON DELETE CASCADE,
				namespace_id INT NULL REFERENCES namespace ON DELETE CASCADE,
				UNIQUE (layer_id, feature_id, namespace_id));`,
			`CREATE INDEX ON layer_feature(layer_id);`,

			`CREATE TABLE IF NOT EXISTS layer_namespace (
				id SERIAL PRIMARY KEY,
				layer_id INT REFERENCES layer ON DELETE CASCADE,
				namespace_id INT REFERENCES namespace ON DELETE CASCADE,
				detector_id INT REFERENCES detector ON DELETE CASCADE,
				UNIQUE (layer_id, namespace_id));`,
			`CREATE INDEX ON layer_namespace(layer_id);`,
		},
		Down: []string{
			`DROP TABLE IF EXISTS layer, layer_detector, layer_feature, layer_namespace CASCADE;`,
		},
	}

	// ancestry contains all meta information around scanned manifest and its
	// layers.
	ancestry = MigrationQuery{
		Up: []string{
			`CREATE TABLE IF NOT EXISTS ancestry (
				id SERIAL PRIMARY KEY,
				name TEXT NOT NULL UNIQUE);`,

			`CREATE TABLE IF NOT EXISTS ancestry_layer (
				id SERIAL PRIMARY KEY,
				ancestry_id INT NOT NULL REFERENCES ancestry ON DELETE CASCADE,
				ancestry_index INT NOT NULL,
				layer_id INT NOT NULL REFERENCES layer ON DELETE RESTRICT,
				UNIQUE (ancestry_id, ancestry_index));`,
			`CREATE INDEX ON ancestry_layer(ancestry_id);`,

			`CREATE TABLE IF NOT EXISTS ancestry_feature(
				id SERIAL PRIMARY KEY,
				ancestry_layer_id INT NOT NULL REFERENCES ancestry_layer ON DELETE CASCADE,
				namespaced_feature_id INT NOT NULL REFERENCES namespaced_feature ON DELETE CASCADE,
				feature_detector_id INT NOT NULL REFERENCES detector ON DELETE CASCADE,
				namespace_detector_id INT REFERENCES detector ON DELETE CASCADE,
				UNIQUE (ancestry_layer_id, namespaced_feature_id));`,

			`CREATE TABLE IF NOT EXISTS ancestry_detector(
				id SERIAL PRIMARY KEY,
				ancestry_id INT NOT NULL REFERENCES ancestry ON DELETE CASCADE,
				detector_id INT NOT NULL REFERENCES detector ON DELETE CASCADE,
				UNIQUE(ancestry_id, detector_id));`,
			`CREATE INDEX ON ancestry_detector(ancestry_id);`,
		},
		Down: []string{
			`DROP TABLE IF EXISTS ancestry, ancestry_layer, ancestry_feature, ancestry_detector CASCADE;`,
		},
	}

	// vulnerability contains the metadata and vulnerability affecting relation.
	vulnerability = MigrationQuery{
		Up: []string{
			`CREATE TYPE severity AS ENUM ('Unknown', 'Negligible', 'Low', 'Medium', 'High', 'Critical', 'Defcon1');`,

			`CREATE TABLE IF NOT EXISTS vulnerability (
				id SERIAL PRIMARY KEY,
				namespace_id INT REFERENCES Namespace,
				name TEXT NOT NULL,
				description TEXT NULL,
				link TEXT NULL,
				severity severity NOT NULL,
				metadata TEXT NULL,
				created_at TIMESTAMP WITH TIME ZONE,
				deleted_at TIMESTAMP WITH TIME ZONE NULL);`,
			`CREATE INDEX ON vulnerability(namespace_id, name);`,
			`CREATE INDEX ON vulnerability(namespace_id);`,

			// vulnerability_affected_feature is a de-normalized table to store
			// the affected features in a independent place other than the
			// feature table to reduce table lock issue, and makes it easier for
			// decoupling updater and the Clair main logic.
			`CREATE TABLE IF NOT EXISTS vulnerability_affected_feature (
				id SERIAL PRIMARY KEY, 
				vulnerability_id INT NOT NULL REFERENCES vulnerability ON DELETE CASCADE,
				feature_name TEXT NOT NULL,
				feature_type INT NOT NULL REFERENCES feature_type ON DELETE CASCADE,
				affected_version TEXT,
				fixedin TEXT);`,
			`CREATE INDEX ON vulnerability_affected_feature(vulnerability_id, feature_name, feature_type);`,

			`CREATE TABLE IF NOT EXISTS vulnerability_affected_namespaced_feature(
				id SERIAL PRIMARY KEY,
				vulnerability_id INT NOT NULL REFERENCES vulnerability ON DELETE CASCADE,
				namespaced_feature_id INT NOT NULL REFERENCES namespaced_feature ON DELETE CASCADE,
				added_by INT NOT NULL REFERENCES vulnerability_affected_feature ON DELETE CASCADE,
				UNIQUE (vulnerability_id, namespaced_feature_id));`,
			`CREATE INDEX ON vulnerability_affected_namespaced_feature(namespaced_feature_id);`,
		},
		Down: []string{
			`DROP TABLE IF EXISTS vulnerability, vulnerability_affected_feature, vulnerability_affected_namespaced_feature CASCADE;`,
			`DROP TYPE IF EXISTS severity;`,
		},
	}

	// updaterLock is the lock to be used by updater to prevent multiple
	// updaters running on the same vulnerability source.
	updaterLock = MigrationQuery{
		Up: []string{
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
		},
		Down: []string{
			`DROP TABLE IF EXISTS KeyValue, Lock CASCADE;`,
		},
	}

	// notification is the vulnerability notification spawned by the
	// vulnerability changes.
	notification = MigrationQuery{
		Up: []string{
			`CREATE TABLE IF NOT EXISTS Vulnerability_Notification (
				id SERIAL PRIMARY KEY,
				name VARCHAR(64) NOT NULL UNIQUE,
				created_at TIMESTAMP WITH TIME ZONE,
				notified_at TIMESTAMP WITH TIME ZONE NULL,
				deleted_at TIMESTAMP WITH TIME ZONE NULL,
				old_vulnerability_id INT NULL REFERENCES Vulnerability ON DELETE CASCADE,
				new_vulnerability_id INT NULL REFERENCES Vulnerability ON DELETE CASCADE);`,
			`CREATE INDEX ON Vulnerability_Notification (notified_at);`,
		},
		Down: []string{
			`DROP TABLE IF EXISTS Vulnerability_Notification CASCADE;`,
		},
	}
)

func init() {
	RegisterMigration(NewSimpleMigration(1,
		[]MigrationQuery{
			entities,
			detector,
			layer,
			ancestry,
			vulnerability,
			updaterLock,
			notification,
		}))
}
