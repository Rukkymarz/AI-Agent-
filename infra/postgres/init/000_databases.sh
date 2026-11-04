#!/usr/bin/env bash
# Creates isolated databases + least-privilege roles for each service. Passwords come from Docker secrets.
set -euo pipefail
read_secret() { tr -d '\n' < "/run/secrets/$1"; }
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<SQL
CREATE ROLE aicos_app LOGIN PASSWORD '$(read_secret pg_aicos_password)';
CREATE ROLE aicos_migrator LOGIN PASSWORD '$(read_secret pg_migrator_password)';
CREATE ROLE keycloak LOGIN PASSWORD '$(read_secret pg_keycloak_password)';
CREATE ROLE n8n LOGIN PASSWORD '$(read_secret pg_n8n_password)';
CREATE ROLE langfuse LOGIN PASSWORD '$(read_secret pg_langfuse_password)';
CREATE DATABASE aicos OWNER aicos_migrator;
CREATE DATABASE keycloak OWNER keycloak;
CREATE DATABASE n8n OWNER n8n;
CREATE DATABASE langfuse OWNER langfuse;
REVOKE ALL ON DATABASE aicos FROM PUBLIC;
GRANT CONNECT ON DATABASE aicos TO aicos_app;
SQL
