INSERT INTO namespace (id, name, version_format) VALUES
(1, 'debian:7', 'dpkg'),
(2, 'debian:8', 'dpkg'),
(3, 'fake:1.0', 'rpm');

INSERT INTO feature (id, name, version, version_format) VALUES
(1, 'wechat', '0.5', 'dpkg'),
(2, 'openssl', '1.0', 'dpkg'),
(3, 'openssl', '2.0', 'dpkg'),
(4, 'fake', '2.0', 'rpm');

INSERT INTO layer (id, hash) VALUES
  (1, 'layer-0'), -- blank
  (2, 'layer-1'), -- debian:7; wechat 0.5, openssl 1.0
  (3, 'layer-2'), -- debian:7; wechat 0.5, openssl 2.0
  (4, 'layer-3a'),-- debian:7; 
  (5, 'layer-3b'),-- debian:8; wechat 0.5, openssl 1.0
  (6, 'layer-4'); -- debian:7, fake:1.0; openssl 2.0 (debian), fake 2.0 (fake)

INSERT INTO layer_namespace(id, layer_id, namespace_id) VALUES
  (1, 2, 1),
  (2, 3, 1),
  (3, 4, 1),
  (4, 5, 2),
  (5, 6, 1),
  (6, 6, 3);

INSERT INTO layer_feature(id, layer_id, feature_id) VALUES
  (1, 2, 1),
  (2, 2, 2),
  (3, 3, 1),
  (4, 3, 3),
  (5, 5, 1),
  (6, 5, 2),
  (7, 6, 4),
  (8, 6, 3);

INSERT INTO layer_lister(id, layer_id, lister) VALUES
  (1, 1, 'dpkg'),
  (2, 2, 'dpkg'),
  (3, 3, 'dpkg'),
  (4, 4, 'dpkg'),
  (5, 5, 'dpkg'),
  (6, 6, 'dpkg'),
  (7, 6, 'rpm');

INSERT INTO layer_detector(id, layer_id, detector) VALUES
  (1, 1, 'os-release'),
  (2, 2, 'os-release'),
  (3, 3, 'os-release'),
  (4, 4, 'os-release'),
  (5, 5, 'os-release'),
  (6, 6, 'os-release'),
  (7, 6, 'apt-sources');

INSERT INTO ancestry (id, name) VALUES
  (1, 'ancestry-1'), -- layer-0, layer-1, layer-2, layer-3a
  (2, 'ancestry-2'), -- layer-0, layer-1, layer-2, layer-3b
  (3, 'ancestry-3'), -- empty; just for testing the vulnerable ancestry
  (4, 'ancestry-4'); -- empty; just for testing the vulnerable ancestry

INSERT INTO ancestry_lister (id, ancestry_id, lister) VALUES
  (1, 1, 'dpkg'),
  (2, 2, 'dpkg');

INSERT INTO ancestry_detector (id, ancestry_id, detector) VALUES
  (1, 1, 'os-release'),
  (2, 2, 'os-release');

INSERT INTO ancestry_layer (id, ancestry_id, layer_id, ancestry_index) VALUES
  (1, 1, 1, 0),(2, 1, 2, 1),(3, 1, 3, 2),(4, 1, 4, 3),
  (5, 2, 1, 0),(6, 2, 2, 1),(7, 2, 3, 2),(8, 2, 5, 3);

INSERT INTO namespaced_feature(id, feature_id, namespace_id) VALUES
  (1, 1, 1), -- wechat 0.5, debian:7
  (2, 2, 1), -- openssl 1.0, debian:7
  (3, 2, 2), -- openssl 1.0, debian:8
  (4, 3, 1); -- openssl 2.0, debian:7

INSERT INTO ancestry_feature (id, ancestry_id, namespaced_feature_id) VALUES
  (1, 1, 1), (2, 1, 4), 
  (3, 2, 1), (4, 2, 3),
  (5, 3, 2), (6, 4, 2); -- assume that ancestry-3 and ancestry-4 are vulnerable.

INSERT INTO vulnerability (id, namespace_id, name, description, link, severity) VALUES
  (1, 1, 'CVE-OPENSSL-1-DEB7', 'A vulnerability affecting OpenSSL < 2.0 on Debian 7.0', 'http://google.com/#q=CVE-OPENSSL-1-DEB7', 'High'),
  (2, 1, 'CVE-NOPE', 'A vulnerability affecting nothing', '', 'Unknown');

INSERT INTO vulnerability (id, namespace_id, name, description, link, severity, deleted_at) VALUES
	(3, 1, 'CVE-DELETED', '', '', 'Unknown', '2017-08-08 17:49:31.668483');
	
INSERT INTO vulnerability_affected_feature(id, vulnerability_id, feature_name, affected_version, fixedin) VALUES
(1, 1, 'openssl', '2.0', '2.0'),
(2, 1, 'libssl', '1.9-abc', '1.9-abc');

INSERT INTO vulnerability_affected_namespaced_feature(id, vulnerability_id, namespaced_feature_id, added_by) VALUES
 (1, 1, 2, 1);

INSERT INTO vulnerability_notification(id, name, created_at, notified_at, deleted_at, old_vulnerability_id, new_vulnerability_id) VALUES
 (1, 'test', NULL, NULL, NULL, 2, 1); -- 'CVE-NOPE' -> 'CVE-OPENSSL-1-DEB7'

SELECT pg_catalog.setval(pg_get_serial_sequence('namespace', 'id'), (SELECT MAX(id) FROM namespace)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('ancestry', 'id'), (SELECT MAX(id) FROM ancestry)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('ancestry_layer', 'id'), (SELECT MAX(id) FROM ancestry_layer)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('ancestry_feature', 'id'), (SELECT MAX(id) FROM ancestry_feature)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('ancestry_detector', 'id'), (SELECT MAX(id) FROM ancestry_detector)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('ancestry_lister', 'id'), (SELECT MAX(id) FROM ancestry_lister)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('feature', 'id'), (SELECT MAX(id) FROM feature)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('namespaced_feature', 'id'), (SELECT MAX(id) FROM namespaced_feature)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('layer', 'id'), (SELECT MAX(id) FROM layer)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('layer_namespace', 'id'), (SELECT MAX(id) FROM layer_namespace)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('layer_detector', 'id'), (SELECT MAX(id) FROM layer_detector)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('layer_lister', 'id'), (SELECT MAX(id) FROM layer_lister)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('vulnerability', 'id'), (SELECT MAX(id) FROM vulnerability)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('vulnerability_affected_feature', 'id'), (SELECT MAX(id) FROM vulnerability_affected_feature)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('vulnerability_affected_namespaced_feature', 'id'), (SELECT MAX(id) FROM vulnerability_affected_namespaced_feature)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('vulnerability_notification', 'id'), (SELECT MAX(id) FROM vulnerability_notification)+1);
