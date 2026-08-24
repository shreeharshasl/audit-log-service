-- The application database is created by POSTGRES_DB. Integration tests (`mvn verify`)
-- use a separate catalog so a failed IT cannot leave the running service's chain dirty.
CREATE DATABASE auditlog_test;
