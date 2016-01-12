INSERT INTO namespace (id, name) VALUES (1, 'debian:7');
INSERT INTO namespace (id, name) VALUES (2, 'debian:8');

INSERT INTO feature (id, namespace_id, name) VALUES (1, 1, 'wechat');
INSERT INTO feature (id, namespace_id, name) VALUES (2, 1, 'openssl');
INSERT INTO feature (id, namespace_id, name) VALUES (4, 1, 'libssl');
INSERT INTO feature (id, namespace_id, name) VALUES (3, 2, 'openssl');
INSERT INTO featureversion (id, feature_id, version) VALUES (1, 1, '0.5');
INSERT INTO featureversion (id, feature_id, version) VALUES (2, 2, '1.0');
INSERT INTO featureversion (id, feature_id, version) VALUES (3, 2, '2.0');
INSERT INTO featureversion (id, feature_id, version) VALUES (4, 3, '1.0');

INSERT INTO layer (id, name, engineversion, parent_id, namespace_id) VALUES (1, 'layer-0', 1, NULL, NULL);
INSERT INTO layer (id, name, engineversion, parent_id, namespace_id) VALUES (2, 'layer-1', 1, 1, 1);
INSERT INTO layer (id, name, engineversion, parent_id, namespace_id) VALUES (3, 'layer-2', 1, 2, 1);
INSERT INTO layer (id, name, engineversion, parent_id, namespace_id) VALUES (4, 'layer-3a', 1, 3, 1);
INSERT INTO layer (id, name, engineversion, parent_id, namespace_id) VALUES (5, 'layer-3b', 1, 3, 2);
INSERT INTO layer_diff_featureversion (id, layer_id, featureversion_id, modification) VALUES (1, 2, 1, 'add');
INSERT INTO layer_diff_featureversion (id, layer_id, featureversion_id, modification) VALUES (2, 2, 2, 'add');
INSERT INTO layer_diff_featureversion (id, layer_id, featureversion_id, modification) VALUES (3, 3, 2, 'del'); -- layer-2: Update Debian:7 OpenSSL 1.0 -> 2.0
INSERT INTO layer_diff_featureversion (id, layer_id, featureversion_id, modification) VALUES (4, 3, 3, 'add'); -- ^
INSERT INTO layer_diff_featureversion (id, layer_id, featureversion_id, modification) VALUES (5, 5, 3, 'del'); -- layer-3b: Delete Debian:7 OpenSSL 2.0
INSERT INTO layer_diff_featureversion (id, layer_id, featureversion_id, modification) VALUES (6, 5, 4, 'add'); -- layer-3b: Add Debian:8 OpenSSL 1.0

INSERT INTO vulnerability (id, namespace_id, name, description, link, severity) VALUES (1, 1, 'CVE-OPENSSL-1-DEB7', 'A vulnerability affecting OpenSSL < 2.0 on Debian 7.0', 'http://google.com/#q=CVE-OPENSSL-1-DEB7', 'High');
INSERT INTO vulnerability_fixedin_feature (id, vulnerability_id, feature_id, version) VALUES (1, 1, 2, '2.0');
INSERT INTO vulnerability_fixedin_feature (id, vulnerability_id, feature_id, version) VALUES (2, 1, 4, '1.9-abc');
INSERT INTO vulnerability_affects_featureversion (id, vulnerability_id, featureversion_id, fixedin_id) VALUES (1, 1, 2, 1); -- CVE-OPENSSL-1-DEB7 affects Debian:7 OpenSSL 1.0
INSERT INTO vulnerability (id, namespace_id, name, description, link, severity) VALUES (2, 1, 'CVE-NOPE', 'A vulnerability affecting nothing', '', 'Unknown');

SELECT pg_catalog.setval(pg_get_serial_sequence('namespace', 'id'), (SELECT MAX(id) FROM namespace)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('feature', 'id'), (SELECT MAX(id) FROM feature)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('featureversion', 'id'), (SELECT MAX(id) FROM featureversion)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('layer', 'id'), (SELECT MAX(id) FROM layer)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('layer_diff_featureversion', 'id'), (SELECT MAX(id) FROM layer_diff_featureversion)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('vulnerability', 'id'), (SELECT MAX(id) FROM vulnerability)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('vulnerability_fixedin_feature', 'id'), (SELECT MAX(id) FROM vulnerability_fixedin_feature)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('vulnerability_affects_featureversion', 'id'), (SELECT MAX(id) FROM vulnerability_affects_featureversion)+1);
SELECT pg_catalog.setval(pg_get_serial_sequence('vulnerability', 'id'), (SELECT MAX(id) FROM vulnerability)+1);
