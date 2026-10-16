-- rollback:       0029
-- description:    rollback auth_user_encryption_keys table
-- author:         Platform Architecture & Security Team
-- date:           2026-10-16

DROP TABLE IF EXISTS auth_user_encryption_keys CASCADE;
