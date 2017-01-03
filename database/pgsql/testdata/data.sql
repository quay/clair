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

INSERT INTO namespace (id, name, version_format) VALUES
  (1, 'debian:7', 'dpkg'),
  (2, 'debian:8', 'dpkg');

INSERT INTO feature (id, namespace_id, name) VALUES
  (1, 1, 'wechat'),
  (2, 1, 'openssl'),
  (4, 1, 'libssl'),
  (3, 2, 'openssl');

INSERT INTO featureversion (id, feature_id, version) VALUES
  (1, 1, '0.5'),
  (2, 2, '1.0'),
  (3, 2, '2.0'),
  (4, 3, '1.0');

INSERT INTO layer (id, name, engineversion, parent_id, namespace_id) VALUES
  (1, 'layer-0', 1, NULL, NULL),
  (2, 'layer-1', 1, 1, 1),
  (3, 'layer-2', 1, 2, 1),
  (4, 'layer-3a', 1, 3, 1),
  (5, 'layer-3b', 1, 3, 2);

INSERT INTO layer_diff_featureversion (id, layer_id, featureversion_id, modification) VALUES
  (1, 2, 1, 'add'),
  (2, 2, 2, 'add'),
  (3, 3, 2, 'del'), -- layer-2: Update Debian:7 OpenSSL 1.0 -> 2.0
  (4, 3, 3, 'add'), -- ^
  (5, 5, 3, 'del'), -- layer-3b: Delete Debian:7 OpenSSL 2.0
  (6, 5, 4, 'add'); -- layer-3b: Add Debian:8 OpenSSL 1.0

INSERT INTO vulnerability (id, namespace_id, name, description, link, severity) VALUES
  (1, 1, 'CVE-OPENSSL-1-DEB7', 'A vulnerability affecting OpenSSL < 2.0 on Debian 7.0', 'http://google.com/#q=CVE-OPENSSL-1-DEB7', 'High'),
  (2, 1, 'CVE-NOPE', 'A vulnerability affecting nothing', '', 'Unknown');

INSERT INTO vulnerability_fixedin_feature (id, vulnerability_id, feature_id, version) VALUES
  (1, 1, 2, '2.0'),
  (2, 1, 4, '1.9-abc');

INSERT INTO vulnerability_affects_featureversion (id, vulnerability_id, featureversion_id, fixedin_id) VALUES
  (1, 1, 2, 1); -- CVE-OPENSSL-1-DEB7 affects Debian:7 OpenSSL 1.0

SELECT pg_catalog.setval(pg_get_serial_sequence('namespace', 'id'), (SELECT MAX(id) FROM namespace)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('feature', 'id'), (SELECT MAX(id) FROM feature)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('featureversion', 'id'), (SELECT MAX(id) FROM featureversion)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('layer', 'id'), (SELECT MAX(id) FROM layer)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('layer_diff_featureversion', 'id'), (SELECT MAX(id) FROM layer_diff_featureversion)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('vulnerability', 'id'), (SELECT MAX(id) FROM vulnerability)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('vulnerability_fixedin_feature', 'id'), (SELECT MAX(id) FROM vulnerability_fixedin_feature)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('vulnerability_affects_featureversion', 'id'), (SELECT MAX(id) FROM vulnerability_affects_featureversion)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('vulnerability', 'id'), (SELECT MAX(id) FROM vulnerability)+1);
