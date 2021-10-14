CREATE USER clair WITH PASSWORD 'clair';
CREATE USER quay WITH PASSWORD 'quay';
CREATE DATABASE indexer WITH OWNER clair;
CREATE DATABASE matcher WITH OWNER clair;
CREATE DATABASE notifier WITH OWNER clair;
CREATE DATABASE quay WITH OWNER quay;
\connect matcher
CREATE EXTENSION "uuid-ossp";
\connect notifier
CREATE EXTENSION "uuid-ossp";
\connect quay
CREATE EXTENSION "pg_trgm";
