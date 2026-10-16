-- rollback:       0034
-- description:    drop auth honeytokens table
-- author:         Platform Architecture & Security Team
-- date:           2026-10-16

DROP INDEX IF EXISTS idx_auth_honeytokens_org;
DROP INDEX IF EXISTS idx_auth_honeytokens_lookup;
DROP TABLE IF EXISTS auth_honeytokens;
