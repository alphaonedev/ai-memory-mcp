-- pgbouncer smoke only (#4734): the image entrypoint stores the role password
-- as SCRAM, but pgbouncer.ini uses auth_type=md5 with an md5 userlist, so the
-- pooler can only log in to a backend holding an md5 verifier. Re-store the
-- verifier as md5 from the container's own POSTGRES_PASSWORD (psql \getenv,
-- PG15+); the value never appears in this file or in the repository.
\getenv smoke_pw POSTGRES_PASSWORD
SET password_encryption = 'md5';
ALTER ROLE ai_memory PASSWORD :'smoke_pw';
