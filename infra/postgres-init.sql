-- Runs once on first Postgres init (docker-entrypoint-initdb.d).
-- The main `secureops` database is created by POSTGRES_DB. Langfuse needs
-- its own database on the same server.
CREATE DATABASE langfuse;
