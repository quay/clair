-- Copyright 2015 clair authors
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- +goose Up

-- -----------------------------------------------------
-- Table Namespace
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS Namespace (
  id SERIAL PRIMARY KEY,
  name VARCHAR(128) NULL);


-- -----------------------------------------------------
-- Table Layer
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS Layer (
  id SERIAL PRIMARY KEY,
  name VARCHAR(128) NOT NULL UNIQUE,
  engineversion SMALLINT NOT NULL,
  parent_id INT NULL REFERENCES Layer ON DELETE CASCADE,
  namespace_id INT NULL REFERENCES Namespace,
  created_at TIMESTAMP WITH TIME ZONE);

CREATE INDEX ON Layer (parent_id);
CREATE INDEX ON Layer (namespace_id);


-- -----------------------------------------------------
-- Table Feature
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS Feature (
  id SERIAL PRIMARY KEY,
  namespace_id INT NOT NULL REFERENCES Namespace,
  name VARCHAR(128) NOT NULL,

  UNIQUE (namespace_id, name));


-- -----------------------------------------------------
-- Table FeatureVersion
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS FeatureVersion (
  id SERIAL PRIMARY KEY,
  feature_id INT NOT NULL REFERENCES Feature,
  version VARCHAR(128) NOT NULL);

CREATE INDEX ON FeatureVersion (feature_id);


-- -----------------------------------------------------
-- Table Layer_diff_FeatureVersion
-- -----------------------------------------------------
CREATE TYPE modification AS ENUM ('add', 'del');

CREATE TABLE IF NOT EXISTS Layer_diff_FeatureVersion (
  id SERIAL PRIMARY KEY,
  layer_id INT NOT NULL REFERENCES Layer ON DELETE CASCADE,
  featureversion_id INT NOT NULL REFERENCES FeatureVersion,
  modification modification NOT NULL,

  UNIQUE (layer_id, featureversion_id));

CREATE INDEX ON Layer_diff_FeatureVersion (layer_id);
CREATE INDEX ON Layer_diff_FeatureVersion (featureversion_id);
CREATE INDEX ON Layer_diff_FeatureVersion (featureversion_id, layer_id);


-- -----------------------------------------------------
-- Table Vulnerability
-- -----------------------------------------------------
CREATE TYPE severity AS ENUM ('Unknown', 'Negligible', 'Low', 'Medium', 'High', 'Critical', 'Defcon1');

CREATE TABLE IF NOT EXISTS Vulnerability (
  id SERIAL PRIMARY KEY,
  namespace_id INT NOT NULL REFERENCES Namespace,
  name VARCHAR(128) NOT NULL,
  description TEXT NULL,
  link VARCHAR(128) NULL,
  severity severity NOT NULL,
  metadata TEXT NULL,
  created_at TIMESTAMP WITH TIME ZONE,
  deleted_at TIMESTAMP WITH TIME ZONE NULL);


-- -----------------------------------------------------
-- Table Vulnerability_FixedIn_Feature
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS Vulnerability_FixedIn_Feature (
  id SERIAL PRIMARY KEY,
  vulnerability_id INT NOT NULL REFERENCES Vulnerability ON DELETE CASCADE,
  feature_id INT NOT NULL REFERENCES Feature,
  version VARCHAR(128) NOT NULL,

  UNIQUE (vulnerability_id, feature_id));

CREATE INDEX ON Vulnerability_FixedIn_Feature (feature_id, vulnerability_id);


-- -----------------------------------------------------
-- Table Vulnerability_Affects_FeatureVersion
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS Vulnerability_Affects_FeatureVersion (
  id SERIAL PRIMARY KEY,
  vulnerability_id INT NOT NULL REFERENCES Vulnerability ON DELETE CASCADE,
  featureversion_id INT NOT NULL REFERENCES FeatureVersion,
  fixedin_id INT NOT NULL REFERENCES Vulnerability_FixedIn_Feature ON DELETE CASCADE,

  UNIQUE (vulnerability_id, featureversion_id));

CREATE INDEX ON Vulnerability_Affects_FeatureVersion (fixedin_id);
CREATE INDEX ON Vulnerability_Affects_FeatureVersion (featureversion_id, vulnerability_id);


-- -----------------------------------------------------
-- Table KeyValue
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS KeyValue (
  id SERIAL PRIMARY KEY,
  key VARCHAR(128) NOT NULL UNIQUE,
  value TEXT);


-- -----------------------------------------------------
-- Table Lock
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS Lock (
  id SERIAL PRIMARY KEY,
  name VARCHAR(64) NOT NULL UNIQUE,
  owner VARCHAR(64) NOT NULL,
  until TIMESTAMP WITH TIME ZONE);

CREATE INDEX ON Lock (owner);


-- -----------------------------------------------------
-- Table VulnerabilityNotification
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS Vulnerability_Notification (
  id SERIAL PRIMARY KEY,
  name VARCHAR(64) NOT NULL UNIQUE,
  created_at TIMESTAMP WITH TIME ZONE,
  notified_at TIMESTAMP WITH TIME ZONE NULL,
  deleted_at TIMESTAMP WITH TIME ZONE NULL,
  old_vulnerability_id INT NULL REFERENCES Vulnerability ON DELETE CASCADE,
  new_vulnerability_id INT NULL REFERENCES Vulnerability ON DELETE CASCADE);

CREATE INDEX ON Vulnerability_Notification (notified_at);

-- +goose Down

DROP TABLE IF EXISTS Namespace,
                     Layer,
                     Feature,
                     FeatureVersion,
                     Layer_diff_FeatureVersion,
                     Vulnerability,
                     Vulnerability_FixedIn_Feature,
                     Vulnerability_Affects_FeatureVersion,
                     Vulnerability_Notification,
                     KeyValue,
                     Lock
            CASCADE;

DROP TYPE IF EXISTS modification,
                    severity
            CASCADE;

