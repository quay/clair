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
  parent_id BIGINT UNSIGNED NULL,
  namespace_id BIGINT UNSIGNED NULL,
  created_at TIMESTAMP,
  FOREIGN KEY(parent_id) REFERENCES Layer(id) ON DELETE CASCADE,
  FOREIGN KEY(namespace_id) REFERENCES Namespace(id),
  INDEX (parent_id),
  INDEX (namespace_id));


-- -----------------------------------------------------
-- Table Feature
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS Feature (
  id SERIAL PRIMARY KEY,
  namespace_id  BIGINT UNSIGNED NOT NULL,
  name VARCHAR(128) NOT NULL,

  FOREIGN KEY(namespace_id) REFERENCES Namespace(ID),
  UNIQUE (namespace_id, name));


-- -----------------------------------------------------
-- Table FeatureVersion
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS FeatureVersion (
  id SERIAL PRIMARY KEY,
  feature_id BIGINT UNSIGNED NOT NULL,
  version VARCHAR(128) NOT NULL,
  FOREIGN KEY(feature_id) REFERENCES Feature(id),
  INDEX (feature_id));


-- -----------------------------------------------------
-- Table Layer_diff_FeatureVersion
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS Layer_diff_FeatureVersion (
  id SERIAL PRIMARY KEY,
  layer_id BIGINT UNSIGNED NOT NULL ,
  featureversion_id BIGINT UNSIGNED NOT NULL ,
  modification ENUM('add', 'del') NOT NULL,

  FOREIGN KEY (layer_id) REFERENCES  Layer(id) ON DELETE CASCADE,
  FOREIGN KEY (featureversion_id) REFERENCES FeatureVersion(id),
  INDEX (layer_id),
  INDEX (featureversion_id),
  InDEX (featureversion_id, layer_id),
  UNIQUE (layer_id, featureversion_id));


-- -----------------------------------------------------
-- Table Vulnerability
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS Vulnerability (
  id SERIAL PRIMARY KEY,
  namespace_id INT NOT NULL REFERENCES Namespace,
  name VARCHAR(128) NOT NULL,
  description TEXT NULL,
  link VARCHAR(128) NULL,
  severity ENUM('Unknown', 'Negligible', 'Low', 'Medium', 'High', 'Critical', 'Defcon1') NOT NULL,
  metadata TEXT NULL,
  created_at TIMESTAMP,
  deleted_at TIMESTAMP NULL);


-- -----------------------------------------------------
-- Table Vulnerability_FixedIn_Feature
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS Vulnerability_FixedIn_Feature (
  id SERIAL PRIMARY KEY,
  vulnerability_id BIGINT UNSIGNED NOT NULL,
  feature_id BIGINT UNSIGNED NOT NULL,
  version VARCHAR(128) NOT NULL,

  INDEX (feature_id, vulnerability_id),
  FOREIGN KEY (vulnerability_id) REFERENCES Vulnerability(id) ON DELETE CASCADE,
  FOREIGN KEY (feature_id) REFERENCES Feature(id),
  UNIQUE (vulnerability_id, feature_id));

-- -----------------------------------------------------
-- Table Vulnerability_Affects_FeatureVersion
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS Vulnerability_Affects_FeatureVersion (
  id SERIAL PRIMARY KEY,
  vulnerability_id BIGINT UNSIGNED NOT NULL,
  featureversion_id BIGINT UNSIGNED NOT NULL,
  fixedin_id BIGINT UNSIGNED NOT NULL,

  INDEX (fixedin_id),
  INDEX (featureversion_id, vulnerability_id),
  FOREIGN KEY (vulnerability_id) REFERENCES Vulnerability(id) ON DELETE CASCADE,
  FOREIGN KEY (fixedin_id) REFERENCES Vulnerability_FixedIn_Feature (id) ON DELETE CASCADE,
  FOREIGN KEY (featureversion_id) REFERENCES FeatureVersion (id),
  UNIQUE (vulnerability_id, featureversion_id));



-- -----------------------------------------------------
-- Table KeyValue
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS KeyValue (
  id SERIAL PRIMARY KEY,
  `key` VARCHAR(128) NOT NULL UNIQUE,
  `value` TEXT);

-- -----------------------------------------------------
-- Table Lock
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `Lock` (
  id SERIAL PRIMARY KEY,
  name VARCHAR(64) NOT NULL UNIQUE,
  owner VARCHAR(64) NOT NULL,
  until TIMESTAMP,

  INDEX (owner));


-- -----------------------------------------------------
-- Table VulnerabilityNotification
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS Vulnerability_Notification (
  id SERIAL PRIMARY KEY,
  name VARCHAR(64) NOT NULL UNIQUE,
  created_at TIMESTAMP ,
  notified_at TIMESTAMP NULL,
  deleted_at TIMESTAMP NULL,
  old_vulnerability_id BIGINT UNSIGNED NULL,
  new_vulnerability_id BIGINT UNSIGNED NULL,

  FOREIGN KEY (old_vulnerability_id) REFERENCES Vulnerability(id) ON DELETE CASCADE,
  FOREIGN KEY (new_vulnerability_id) REFERENCES Vulnerability(id) ON DELETE CASCADE,
  INDEX (notified_at));

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
                     `KeyValue`,
                     `Lock`
            CASCADE;
