-- initialize entities
INSERT INTO namespace (id, name, version_format) VALUES
  (1, 'debian:7', 'dpkg'),
  (2, 'debian:8', 'dpkg'),
  (3, 'fake:1.0', 'rpm'),
  (4, 'cpe:/o:redhat:enterprise_linux:7::server', 'rpm');

INSERT INTO feature (id, name, version, version_format, type) VALUES
  (1, 'ourchat', '0.5', 'dpkg', 1),
  (2, 'openssl', '1.0', 'dpkg', 1),
  (3, 'openssl', '2.0', 'dpkg', 1),
  (4, 'fake', '2.0', 'rpm', 1),
  (5, 'mount', '2.31.1-0.4ubuntu3.1', 'dpkg', 2);

INSERT INTO namespaced_feature(id, feature_id, namespace_id) VALUES
  (1, 1, 1), -- ourchat 0.5, debian:7
  (2, 2, 1), -- openssl 1.0, debian:7
  (3, 2, 2), -- openssl 1.0, debian:8
  (4, 3, 1); -- openssl 2.0, debian:7

INSERT INTO detector(id, name, version, dtype) VALUES
  (1, 'os-release', '1.0', 'namespace'),
  (2, 'dpkg', '1.0', 'feature'),
  (3, 'rpm', '1.0', 'feature'),
  (4, 'apt-sources', '1.0', 'namespace');

-- initialize layers
INSERT INTO layer (id, hash) VALUES
  (1, 'layer-0'), -- blank
  (2, 'layer-1'), -- debian:7; ourchat 0.5, openssl 1.0
  (3, 'layer-2'), -- debian:7; ourchat 0.5, openssl 2.0
  (4, 'layer-3a'),-- debian:7; 
  (5, 'layer-3b'),-- debian:8; ourchat 0.5, openssl 1.0
  (6, 'layer-4'); -- debian:7, fake:1.0; openssl 2.0 (debian), fake 2.0 (fake)

INSERT INTO layer_namespace(id, layer_id, namespace_id, detector_id) VALUES
  (1, 2, 1, 1), -- layer-1: debian:7
  (2, 3, 1, 1), -- layer-2: debian:7
  (3, 4, 1, 1), -- layer-3a: debian:7
  (4, 5, 2, 1), -- layer-3b: debian:8
  (5, 6, 1, 1), -- layer-4: debian:7
  (6, 6, 3, 4); -- layer-4: fake:1.0

INSERT INTO layer_feature(id, layer_id, feature_id, detector_id) VALUES
  (1, 2, 1, 2), -- layer-1: ourchat 0.5
  (2, 2, 2, 2), -- layer-1: openssl 1.0
  (3, 3, 1, 2), -- layer-2: ourchat 0.5
  (4, 3, 3, 2), -- layer-2: openssl 2.0
  (5, 5, 1, 2), -- layer-3b: ourchat 0.5
  (6, 5, 2, 2), -- layer-3b: openssl 1.0
  (7, 6, 4, 3), -- layer-4: fake 2.0
  (8, 6, 3, 2); -- layer-4: openssl 2.0

INSERT INTO layer_detector(layer_id, detector_id) VALUES
  (1, 1),
  (2, 1),
  (3, 1),
  (4, 1),
  (5, 1),
  (6, 1),
  (6, 4),
  (1, 2),
  (2, 2),
  (3, 2),
  (4, 2),
  (5, 2),
  (6, 2),
  (6, 3);

INSERT INTO ancestry (id, name) VALUES
  (1, 'ancestry-1'), -- layer-0, layer-1, layer-2, layer-3a
  (2, 'ancestry-2'), -- layer-0, layer-1, layer-2, layer-3b
  (3, 'ancestry-3'), -- layer-0
  (4, 'ancestry-4'); -- layer-0

INSERT INTO ancestry_detector (ancestry_id, detector_id) VALUES
  (1, 2),
  (2, 2),
  (1, 1),
  (2, 1);

INSERT INTO ancestry_layer (id, ancestry_id, layer_id, ancestry_index) VALUES
  -- ancestry-1: layer-0, layer-1, layer-2, layer-3a
  (1, 1, 1, 0),(2, 1, 2, 1),(3, 1, 3, 2),(4, 1, 4, 3),
  -- ancestry-2: layer-0, layer-1, layer-2, layer-3b
  (5, 2, 1, 0),(6, 2, 2, 1),(7, 2, 3, 2),(8, 2, 5, 3),
  -- ancestry-3: layer-1
  (9, 3, 2, 0),
  -- ancestry-4: layer-1
  (10, 4, 2, 0);

-- assume that ancestry-3 and ancestry-4 are vulnerable.
INSERT INTO ancestry_feature (id, ancestry_layer_id, namespaced_feature_id, feature_detector_id, namespace_detector_id) VALUES
  -- ancestry-1: 
    -- layer-2: ourchat 0.5 <- detected by dpkg 1.0 (2); debian: 7 <- detected by os-release 1.0 (1)
    -- layer-2: openssl 2.0, debian:7
  (1, 3, 1, 2, 1), (2, 3, 4, 2, 1), 
  -- ancestry 2:
    -- 1(ourchat 0.5; debian:7 layer-2)
    -- 3(openssl 1.0; debian:8 layer-3b)
  (3, 7, 1, 2, 1), (4, 8, 3, 2, 1),
  -- ancestry-3:
    -- 2(openssl 1.0, debian:7 layer-1)
    -- 1(ourchat 0.5, debian:7 layer-1)
  (5, 9, 2, 2, 1), (6, 9, 1, 2, 1),   -- vulnerable
  -- ancestry-4:
    -- same as ancestry-3
  (7, 10, 2, 2, 1), (8, 10, 1, 2, 1); -- vulnerable

INSERT INTO vulnerability (id, namespace_id, name, description, link, severity) VALUES
  (1, 1, 'CVE-OPENSSL-1-DEB7', 'A vulnerability affecting OpenSSL < 2.0 on Debian 7.0', 'http://google.com/#q=CVE-OPENSSL-1-DEB7', 'High'),
  (2, 1, 'CVE-NOPE', 'A vulnerability affecting nothing', '', 'Unknown');

INSERT INTO vulnerability (id, namespace_id, name, description, link, severity, deleted_at) VALUES
	(3, 1, 'CVE-DELETED', '', '', 'Unknown', '2017-08-08 17:49:31.668483');
	
INSERT INTO vulnerability_affected_feature(id, vulnerability_id, feature_name, affected_version, fixedin, feature_type) VALUES
(1, 1, 'openssl', '2.0', '2.0', 1),
(2, 1, 'libssl', '1.9-abc', '1.9-abc', 1);

INSERT INTO vulnerability_affected_namespaced_feature(id, vulnerability_id, namespaced_feature_id, added_by) VALUES
 (1, 1, 2, 1);

INSERT INTO vulnerability_notification(id, name, created_at, notified_at, deleted_at, old_vulnerability_id, new_vulnerability_id) VALUES
 (1, 'test', NULL, NULL, NULL, 2, 1); -- 'CVE-NOPE' -> 'CVE-OPENSSL-1-DEB7'

SELECT pg_catalog.setval(pg_get_serial_sequence('feature', 'id'), (SELECT MAX(id) FROM feature)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('namespace', 'id'), (SELECT MAX(id) FROM namespace)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('namespaced_feature', 'id'), (SELECT MAX(id) FROM namespaced_feature)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('detector', 'id'), (SELECT MAX(id) FROM detector)+1);

SELECT pg_catalog.setval(pg_get_serial_sequence('ancestry', 'id'), (SELECT MAX(id) FROM ancestry)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('ancestry_layer', 'id'), (SELECT MAX(id) FROM ancestry_layer)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('ancestry_feature', 'id'), (SELECT MAX(id) FROM ancestry_feature)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('ancestry_detector', 'id'), (SELECT MAX(id) FROM ancestry_detector)+1);

SELECT pg_catalog.setval(pg_get_serial_sequence('layer', 'id'), (SELECT MAX(id) FROM layer)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('layer_feature', 'id'), (SELECT MAX(id) FROM layer_feature)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('layer_namespace', 'id'), (SELECT MAX(id) FROM layer_namespace)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('layer_detector', 'id'), (SELECT MAX(id) FROM layer_detector)+1);

SELECT pg_catalog.setval(pg_get_serial_sequence('vulnerability', 'id'), (SELECT MAX(id) FROM vulnerability)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('vulnerability_affected_feature', 'id'), (SELECT MAX(id) FROM vulnerability_affected_feature)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('vulnerability_affected_namespaced_feature', 'id'), (SELECT MAX(id) FROM vulnerability_affected_namespaced_feature)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('vulnerability_notification', 'id'), (SELECT MAX(id) FROM vulnerability_notification)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('detector', 'id'), (SELECT MAX(id) FROM detector)+1);
