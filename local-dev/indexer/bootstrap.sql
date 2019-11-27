--- Scanner
--- a unique versioned scanner which is responsible
--- for finding packages and distributions in a layer
CREATE TABLE scanner (
    id SERIAL PRIMARY KEY,
    name text NOT NULL,
    version text NOT NULL,
    kind text NOT NULL
);
CREATE UNIQUE INDEX scanner_unique_idx ON scanner (name, kind, version);

--- ScannerList
--- a relation informing us if a manifest hash has 
--- been scanned by a particular scanner
CREATE TABLE scannerlist (
    id SERIAL PRIMARY KEY,
    manifest_hash text,
    scanner_id int REFERENCES scanner(id)
);
CREATE INDEX scannerlist_manifest_hash_idx ON scannerlist (manifest_hash);

--- IndexReport
--- the jsonb serialized result of a scan for a particular
--- manifest
CREATE TABLE indexreport (
    manifest_hash text PRIMARY KEY,
    state text,
    scan_result jsonb
);
CREATE INDEX indexreport_manifest_hash_idx ON indexreport (manifest_hash);

-- Distribution
--- a unique distribution discovered by a scanner
CREATE TABLE dist (
    id SERIAL PRIMARY KEY,
    name text,
    did text, -- os-release id field
    version text,
    version_code_name text,
    version_id text,
    arch text,
    cpe text,
    pretty_name text
);
CREATE UNIQUE INDEX dist_unique_idx ON dist (name, did, version, version_code_name, version_id, arch, cpe, pretty_name);

--- DistributionScanArtifact
--- A relation linking discovered distributions to a layer
CREATE TABLE dist_scanartifact (
    id SERIAL PRIMARY KEY,
    dist_id int REFERENCES dist(id),
    scanner_id int REFERENCES scanner(id),
    layer_hash text
);
CREATE UNIQUE INDEX dist_scanartifact_unique_idx ON dist_scanartifact (layer_hash, dist_id, scanner_id);

--- Package
--- a unique package discovered by a scanner
CREATE TABLE package (
    id SERIAL PRIMARY KEY,
    name text NOT NULL,
    kind text NOT NULL,
    version text NOT NULL
);
CREATE UNIQUE INDEX package_unique_idx ON package (name, version, kind);

--- PackageScanArtifact
--- A relation linking discovered packages with the 
--- layer hash it was found
CREATE TABLE package_scanartifact (
    id SERIAL PRIMARY KEY,
    layer_hash text,
    package_id int REFERENCES package(id),
    source_id int REFERENCES package(id),
    scanner_id int REFERENCES scanner(id),
    package_db text,
    repository_hint text
);
CREATE UNIQUE INDEX package_scanartifact_unique_idx ON package_scanartifact (layer_hash, package_id, source_id, scanner_id);

--- Repository
--- a unique package repository discovered by a scanner
CREATE TABLE repo (
    id SERIAL PRIMARY KEY,
    name text NOT NULL,
    key text,
    uri text
);
CREATE UNIQUE INDEX repo_unique_idx ON repo (name, key, uri);

--- RepositoryScanArtifact
--- A relation linking discovered distributions to a layer
CREATE TABLE repo_scanartifact (
    id SERIAL PRIMARY KEY,
    repo_id int REFERENCES repo(id),
    scanner_id int REFERENCES scanner(id),
    layer_hash text
);
CREATE UNIQUE INDEX repo_scanartifact_unique_idx ON repo_scanartifact (layer_hash, repo_id, scanner_id);
