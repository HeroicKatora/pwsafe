#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
	CREATE USER synapse_user;
	CREATE DATABASE synapse
	  WITH OWNER = synapse_user;
	GRANT ALL PRIVILEGES ON DATABASE synapse TO synapse_user;
EOSQL
