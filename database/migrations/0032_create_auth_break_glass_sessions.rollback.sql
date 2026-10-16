-- rollback:       0032
-- description:    rollback create auth_break_glass_sessions table
-- author:         Platform Architecture & Security Team
-- date:           2026-10-16
-- depends_on:     0032_create_auth_break_glass_sessions.sql
-- reversible:     YES

DROP TABLE IF EXISTS auth_break_glass_sessions CASCADE;
