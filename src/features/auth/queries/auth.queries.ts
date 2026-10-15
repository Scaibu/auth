export const AUTH_QUERIES = {
  TENANT_RLS: {
    SET_LOCAL_TENANT_CONTEXT: `SELECT set_config('app.current_org_id', $1, true)`,
  },
  FLOW_CREATE_ORGANIZATION: {
    CHECK_ORG_NAME: `SELECT id FROM auth_organizations WHERE name = $1 AND deleted_at IS NULL LIMIT 1`,
    INSERT_ORG: `INSERT INTO auth_organizations (id, name, slug) VALUES ($1, $2, $3)`,
    INSERT_USER_ORG: `INSERT INTO auth_user_organizations (user_id, org_id, role) VALUES ($1, $2, $3) ON CONFLICT (user_id, org_id) DO NOTHING`,
    LIST_BY_USER: `
      SELECT o.id, o.name, o.slug
      FROM auth_organizations o
      WHERE o.deleted_at IS NULL
        AND (
          EXISTS (SELECT 1 FROM auth_users u WHERE u.id = $1 AND u.org_id = o.id AND u.deleted_at IS NULL)
          OR EXISTS (SELECT 1 FROM auth_user_organizations uo WHERE uo.user_id = $1 AND uo.org_id = o.id)
        )
    `,
    GET_BY_ID: `SELECT id, name, slug FROM auth_organizations WHERE id = $1 AND deleted_at IS NULL LIMIT 1`,
    UPDATE_NAME: `UPDATE auth_organizations SET name = $1 WHERE id = $2 AND deleted_at IS NULL`,
    UPDATE_SLUG: `UPDATE auth_organizations SET slug = $1 WHERE id = $2 AND deleted_at IS NULL`,
  },
  FLOW_DELETE_ORGANIZATION: {
    SOFT_DELETE_ORG: `UPDATE auth_organizations SET deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND deleted_at IS NULL`,
    CASCADE_SOFT_DELETE_USERS: `UPDATE auth_users SET deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE org_id = $1 AND deleted_at IS NULL`,
    CASCADE_SOFT_DELETE_KEYS: `UPDATE auth_api_keys SET deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE org_id = $1 AND deleted_at IS NULL`,
    CASCADE_SOFT_DELETE_LOGS: `UPDATE auth_audit_logs SET deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE org_id = $1 AND deleted_at IS NULL`,
  },
  FLOW_CREATE_USER: {
    FIND_ORG_BY_ID: `SELECT id, name FROM auth_organizations WHERE id = $1 AND deleted_at IS NULL LIMIT 1`,
    INSERT_USER: `INSERT INTO auth_users (id, email, password_hash, name, org_id, org_name, role, user_permissions) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    INSERT_USER_ORG: `INSERT INTO auth_user_organizations (user_id, org_id, role) VALUES ($1, $2, $3) ON CONFLICT (user_id, org_id) DO NOTHING`,
    LIST_BY_ORG: `SELECT id, email, password_hash, name, org_id, org_name, role, blocked, user_permissions, email_verified, mfa_enabled, mfa_secret, mfa_enrolled_at_ms FROM auth_users WHERE org_id = $1 AND deleted_at IS NULL`,
    UNBLOCK_USER: `UPDATE auth_users SET blocked = FALSE, blocked_at = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND deleted_at IS NULL`,
    UPDATE_PROFILE_NAME: `UPDATE auth_users SET name = $1 WHERE id = $2 AND deleted_at IS NULL`,
    UPDATE_ROLE: `UPDATE auth_users SET role = $1 WHERE id = $2 AND deleted_at IS NULL`,
    UPDATE_PERMISSIONS: `UPDATE auth_users SET user_permissions = $1 WHERE id = $2 AND deleted_at IS NULL`,
  },
  FLOW_BLOCK_USER: {
    BLOCK_USER: `UPDATE auth_users SET blocked = TRUE, blocked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND deleted_at IS NULL`,
  },
  FLOW_DELETE_USER: {
    SOFT_DELETE_USER: `UPDATE auth_users SET deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND deleted_at IS NULL`,
  },
  FLOW_RETENTION_PURGE: {
    PURGE_ORGS: `DELETE FROM auth_organizations WHERE deleted_at < NOW() - INTERVAL '30 days'`,
    PURGE_USERS: `DELETE FROM auth_users WHERE deleted_at < NOW() - INTERVAL '30 days'`,
    PURGE_KEYS: `DELETE FROM auth_api_keys WHERE deleted_at < NOW() - INTERVAL '30 days'`,
    PURGE_LOGS: `DELETE FROM auth_audit_logs WHERE deleted_at < NOW() - INTERVAL '30 days'`,
    PURGE_RESETS: `DELETE FROM auth_password_resets WHERE deleted_at < NOW() - INTERVAL '30 days'`,
    PURGE_DENYLIST: `DELETE FROM auth_token_denylist WHERE expires_at_ms < $1`,
    PURGE_REFRESH_TOKENS: `DELETE FROM auth_refresh_tokens WHERE (is_revoked = TRUE AND created_at_ms < $1) OR expires_at_ms < $1`,
  },
  FLOW_SIGN_UP: {
    CHECK_ORG_EXISTS: `SELECT id FROM auth_organizations WHERE (name = $1 OR slug = $2) AND deleted_at IS NULL LIMIT 1`,
    INSERT_ORG: `INSERT INTO auth_organizations (id, name, slug) VALUES ($1, $2, $3)`,
    INSERT_USER: `INSERT INTO auth_users (id, email, password_hash, name, org_id, org_name, role, user_permissions) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    INSERT_USER_ORG: `INSERT INTO auth_user_organizations (user_id, org_id, role) VALUES ($1, $2, $3) ON CONFLICT (user_id, org_id) DO NOTHING`,
  },
  FLOW_SIGN_IN: {
    FIND_USER_BY_EMAIL: `SELECT id, email, password_hash, name, org_id, org_name, role, blocked, user_permissions, email_verified, mfa_enabled, mfa_secret, mfa_enrolled_at_ms FROM auth_users WHERE email = $1 AND deleted_at IS NULL LIMIT 1`,
    RECORD_AUDIT_LOG: `INSERT INTO auth_audit_logs (id, user_id, org_id, event_type, ip_address, user_agent, timestamp_ms) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
  },
  FLOW_SESSION_VERIFY: {
    FIND_USER_BY_ID: `SELECT id, email, password_hash, name, org_id, org_name, role, blocked, user_permissions, email_verified, mfa_enabled, mfa_secret, mfa_enrolled_at_ms FROM auth_users WHERE id = $1 AND deleted_at IS NULL LIMIT 1`,
    ADD_TOKEN_DENYLIST: `INSERT INTO auth_token_denylist (token_hash, expires_at_ms) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
    CHECK_TOKEN_DENYLIST: `SELECT 1 FROM auth_token_denylist WHERE token_hash = $1 AND expires_at_ms > $2 LIMIT 1`,
  },
  FLOW_FORGOT_PASSWORD: {
    INSERT_RESET_TOKEN: `INSERT INTO auth_password_resets (token_hash, user_id, expires_at_ms, used) VALUES ($1, $2, $3, $4)`,
    FIND_RESET_TOKEN: `SELECT token_hash, user_id, expires_at_ms, used FROM auth_password_resets WHERE token_hash = $1 AND deleted_at IS NULL LIMIT 1`,
  },
  FLOW_RESET_PASSWORD: {
    UPDATE_PASSWORD_HASH: `UPDATE auth_users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 AND deleted_at IS NULL`,
    MARK_TOKEN_USED: `UPDATE auth_password_resets SET used = TRUE, updated_at = CURRENT_TIMESTAMP WHERE token_hash = $1 AND deleted_at IS NULL`,
  },
  FLOW_CREATE_API_KEY: {
    INSERT_API_KEY: `INSERT INTO auth_api_keys (key_id, org_id, key_type, key_hash, prefix, name, permissions, created_at_ms, revoked, expires_at_ms, ip_allowlist, rate_quota_rpm, total_requests_count, anomaly_flag, anomaly_flagged_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
    LIST_BY_ORG: `SELECT key_id, org_id, key_type, key_hash, prefix, name, permissions, created_at_ms, revoked, expires_at_ms, last_used_at_ms, last_used_ip, ip_allowlist, rate_quota_rpm, total_requests_count, anomaly_flag, anomaly_flagged_at_ms FROM auth_api_keys WHERE org_id = $1 AND deleted_at IS NULL`,
  },
  FLOW_VERIFY_API_KEY: {
    FIND_API_KEY_BY_HASH: `SELECT key_id, org_id, key_type, key_hash, prefix, name, permissions, created_at_ms, revoked, expires_at_ms, last_used_at_ms, last_used_ip, ip_allowlist, rate_quota_rpm, total_requests_count, anomaly_flag, anomaly_flagged_at_ms FROM auth_api_keys WHERE key_hash = $1 AND deleted_at IS NULL LIMIT 1`,
  },
  FLOW_REVOKE_API_KEY: {
    REVOKE_API_KEY_BY_ID: `UPDATE auth_api_keys SET revoked = TRUE, updated_at = CURRENT_TIMESTAMP WHERE key_id = $1 AND deleted_at IS NULL`,
  },
  FLOW_API_KEY_USAGE: {
    UPDATE_USAGE: `UPDATE auth_api_keys SET last_used_at_ms = $1, last_used_ip = $2, updated_at = CURRENT_TIMESTAMP WHERE key_id = $3 AND deleted_at IS NULL`,
    INCREMENT_REQUEST_COUNT: `UPDATE auth_api_keys SET total_requests_count = total_requests_count + 1, updated_at = CURRENT_TIMESTAMP WHERE key_id = $1 AND deleted_at IS NULL`,
  },
  FLOW_API_KEY_ALLOWLIST: {
    UPDATE_ALLOWLIST: `UPDATE auth_api_keys SET ip_allowlist = $1, updated_at = CURRENT_TIMESTAMP WHERE key_id = $2 AND deleted_at IS NULL RETURNING key_id, org_id, ip_allowlist, rate_quota_rpm`,
    GET_KEY_META: `SELECT key_id, org_id, ip_allowlist, rate_quota_rpm, anomaly_flag FROM auth_api_keys WHERE key_id = $1 AND deleted_at IS NULL LIMIT 1`,
  },
  FLOW_API_KEY_ANOMALY: {
    FLAG_KEY: `UPDATE auth_api_keys SET anomaly_flag = TRUE, anomaly_flagged_at_ms = $1, updated_at = CURRENT_TIMESTAMP WHERE key_id = $2 AND deleted_at IS NULL`,
  },
  FLOW_EMAIL_VERIFICATION: {
    INSERT_TOKEN: `INSERT INTO auth_email_verifications (token_hash, user_id, email, expires_at_ms, used) VALUES ($1, $2, $3, $4, $5)`,
    FIND_TOKEN: `SELECT token_hash, user_id, email, expires_at_ms, used FROM auth_email_verifications WHERE token_hash = $1 AND deleted_at IS NULL LIMIT 1`,
    MARK_VERIFIED: `UPDATE auth_email_verifications SET used = TRUE, updated_at = CURRENT_TIMESTAMP WHERE token_hash = $1 AND deleted_at IS NULL`,
    SET_USER_EMAIL_VERIFIED: `UPDATE auth_users SET email_verified = TRUE, updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND deleted_at IS NULL`,
  },
  FLOW_MFA: {
    SET_SECRET: `UPDATE auth_users SET mfa_secret = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 AND deleted_at IS NULL`,
    ENABLE_MFA: `UPDATE auth_users SET mfa_enabled = TRUE, mfa_enrolled_at_ms = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 AND deleted_at IS NULL`,
    INSERT_RECOVERY_CODE: `INSERT INTO auth_recovery_codes (id, user_id, code_hash, used, created_at_ms) VALUES ($1, $2, $3, FALSE, $4)`,
    FIND_RECOVERY_CODE: `SELECT id, user_id, code_hash, used FROM auth_recovery_codes WHERE user_id = $1 AND code_hash = $2 AND deleted_at IS NULL LIMIT 1`,
    CONSUME_RECOVERY_CODE: `UPDATE auth_recovery_codes SET used = TRUE, used_at_ms = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 AND deleted_at IS NULL`,
  },
  FLOW_AUDIT_LOGS: {
    FETCH_LOGS_BY_USER: `SELECT id, user_id, org_id, event_type, ip_address, user_agent, timestamp_ms FROM auth_audit_logs WHERE user_id = $1 AND deleted_at IS NULL ORDER BY timestamp_ms DESC LIMIT 100`,
    FETCH_LOGS_BY_USER_FILTERED: `
      SELECT id, user_id, org_id, event_type, ip_address, user_agent, timestamp_ms
      FROM auth_audit_logs
      WHERE user_id = $1
        AND deleted_at IS NULL
        AND ($2::text IS NULL OR event_type = $2)
        AND ($3::bigint IS NULL OR timestamp_ms >= $3)
        AND ($4::bigint IS NULL OR timestamp_ms <= $4)
      ORDER BY timestamp_ms DESC
      LIMIT 100
    `,
  },
  FLOW_REFRESH_TOKEN: {
    INSERT_FAMILY: `INSERT INTO auth_refresh_token_families (id, user_id, created_at_ms, is_revoked) VALUES ($1, $2, $3, FALSE)`,
    FIND_FAMILY: `SELECT id, user_id, is_revoked, revoked_reason FROM auth_refresh_token_families WHERE id = $1 LIMIT 1`,
    REVOKE_FAMILY: `UPDATE auth_refresh_token_families SET is_revoked = TRUE, revoked_reason = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2`,
    INSERT_TOKEN: `INSERT INTO auth_refresh_tokens (token_id, family_id, user_id, token_hash, generation, is_revoked, expires_at_ms, created_at_ms, created_ip, user_agent) VALUES ($1, $2, $3, $4, $5, FALSE, $6, $7, $8, $9)`,
    FIND_TOKEN_BY_HASH: `SELECT token_id, family_id, user_id, token_hash, generation, is_revoked, expires_at_ms, created_at_ms, consumed_at_ms FROM auth_refresh_tokens WHERE token_hash = $1 LIMIT 1`,
    CONSUME_TOKEN: `UPDATE auth_refresh_tokens SET consumed_at_ms = $1 WHERE token_id = $2`,
    REVOKE_TOKEN_FAMILY_TOKENS: `UPDATE auth_refresh_tokens SET is_revoked = TRUE WHERE family_id = $1`,
    LIST_ACTIVE_FAMILIES: `
      SELECT f.id AS family_id, f.user_id, f.created_at_ms,
             COALESCE(lat.consumed_at_ms, lat.created_at_ms, f.created_at_ms) AS last_active_at_ms,
             lat.created_ip,
             lat.user_agent
      FROM auth_refresh_token_families f
      CROSS JOIN LATERAL (
        SELECT t.consumed_at_ms, t.created_at_ms, t.created_ip, t.user_agent
        FROM auth_refresh_tokens t
        WHERE t.family_id = f.id AND t.is_revoked = FALSE AND t.expires_at_ms > $2
        ORDER BY t.generation DESC
        LIMIT 1
      ) lat
      WHERE f.user_id = $1 AND f.is_revoked = FALSE
      ORDER BY last_active_at_ms DESC
    `,
    REVOKE_OTHER_FAMILIES: `UPDATE auth_refresh_token_families SET is_revoked = TRUE, revoked_reason = $1, updated_at = CURRENT_TIMESTAMP WHERE user_id = $2 AND id != $3 AND is_revoked = FALSE`,
    REVOKE_OTHER_TOKENS: `UPDATE auth_refresh_tokens SET is_revoked = TRUE WHERE user_id = $1 AND family_id != $2 AND is_revoked = FALSE`,
  },
  FLOW_FEDERATED_IDENTITY: {
    FIND_BY_PROVIDER_SUBJECT: `SELECT id, user_id, provider, provider_subject_id, email, created_at_ms, updated_at_ms FROM auth_federated_identities WHERE provider = $1 AND provider_subject_id = $2 LIMIT 1`,
    FIND_BY_USER_AND_PROVIDER: `SELECT id, user_id, provider, provider_subject_id, email, created_at_ms, updated_at_ms FROM auth_federated_identities WHERE user_id = $1 AND provider = $2 LIMIT 1`,
    LIST_BY_USER_ID: `SELECT id, user_id, provider, provider_subject_id, email, created_at_ms, updated_at_ms FROM auth_federated_identities WHERE user_id = $1 ORDER BY created_at_ms ASC`,
    INSERT_IDENTITY: `INSERT INTO auth_federated_identities (id, user_id, provider, provider_subject_id, email, created_at_ms, updated_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    DELETE_IDENTITY: `DELETE FROM auth_federated_identities WHERE user_id = $1 AND provider = $2`,
    COUNT_BY_USER_ID: `SELECT COUNT(*) AS count FROM auth_federated_identities WHERE user_id = $1`,
  },
  FLOW_DOMAIN_CLAIM: {
    INSERT_DOMAIN: `INSERT INTO auth_organization_domains (id, org_id, domain_name, status, verification_token, verification_method, default_role, auto_join_enabled, created_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    FIND_BY_ID: `SELECT id, org_id, domain_name, status, verification_token, verification_method, default_role, auto_join_enabled, created_at_ms, verified_at_ms, last_checked_at_ms FROM auth_organization_domains WHERE id = $1 AND deleted_at IS NULL LIMIT 1`,
    FIND_BY_NAME: `SELECT id, org_id, domain_name, status, verification_token, verification_method, default_role, auto_join_enabled, created_at_ms, verified_at_ms, last_checked_at_ms FROM auth_organization_domains WHERE domain_name = $1 AND deleted_at IS NULL LIMIT 1`,
    LIST_BY_ORG_ID: `SELECT id, org_id, domain_name, status, verification_token, verification_method, default_role, auto_join_enabled, created_at_ms, verified_at_ms, last_checked_at_ms FROM auth_organization_domains WHERE org_id = $1 AND deleted_at IS NULL ORDER BY created_at_ms DESC`,
    UPDATE_STATUS: `UPDATE auth_organization_domains SET status = $1, verified_at_ms = COALESCE($2, verified_at_ms), last_checked_at_ms = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $4 AND deleted_at IS NULL`,
    UPDATE_SETTINGS: `UPDATE auth_organization_domains SET auto_join_enabled = $1, default_role = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3 AND deleted_at IS NULL`,
    SOFT_DELETE: `UPDATE auth_organization_domains SET deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND deleted_at IS NULL`,
    LIST_PENDING_OR_VERIFIED: `SELECT id, org_id, domain_name, status, verification_token, verification_method, default_role, auto_join_enabled, created_at_ms, verified_at_ms, last_checked_at_ms FROM auth_organization_domains WHERE deleted_at IS NULL AND status IN ('PENDING_VERIFICATION', 'VERIFIED')`,
  },
  FLOW_BLOCKED_DOMAINS: {
    FIND_BY_NAME: `SELECT domain_name, category, reason, created_at_ms, updated_at_ms FROM auth_blocked_domains WHERE domain_name = $1 LIMIT 1`,
    LIST_ALL: `SELECT domain_name, category, reason, created_at_ms, updated_at_ms FROM auth_blocked_domains ORDER BY domain_name ASC`,
    INSERT: `INSERT INTO auth_blocked_domains (domain_name, category, reason, created_at_ms, updated_at_ms) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (domain_name) DO UPDATE SET category = EXCLUDED.category, reason = EXCLUDED.reason, updated_at_ms = EXCLUDED.updated_at_ms, updated_at = CURRENT_TIMESTAMP`,
    DELETE: `DELETE FROM auth_blocked_domains WHERE domain_name = $1`,
  },
  FLOW_LOGIN_HISTORY: {
    INSERT: `INSERT INTO auth_login_history (id, user_id, ip_address, latitude, longitude, asn, is_datacenter, device_fingerprint, risk_score, created_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
    FIND_LATEST_BY_USER: `SELECT id, user_id, ip_address, latitude, longitude, asn, is_datacenter, device_fingerprint, risk_score, created_at_ms FROM auth_login_history WHERE user_id = $1 ORDER BY created_at_ms DESC LIMIT 1`,
  },
  FLOW_RELATION_TUPLES: {
    INSERT: `INSERT INTO auth_relation_tuples (id, org_id, subject_type, subject_id, relation, object_type, object_id, conditions, status, expires_at_ms, granted_by, version, created_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) ON CONFLICT (org_id, subject_type, subject_id, relation, object_type, object_id) DO UPDATE SET conditions = EXCLUDED.conditions, status = EXCLUDED.status, expires_at_ms = EXCLUDED.expires_at_ms, version = auth_relation_tuples.version + 1, updated_at = CURRENT_TIMESTAMP`,
    DELETE: `UPDATE auth_relation_tuples SET status = 'REVOKED', deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE org_id = $1 AND subject_type = $2 AND subject_id = $3 AND relation = $4 AND object_type = $5 AND object_id = $6 AND deleted_at IS NULL`,
    FIND_FILTERED_BASE: `SELECT id, org_id, subject_type, subject_id, relation, object_type, object_id, conditions, status, expires_at_ms, granted_by, version, created_at_ms FROM auth_relation_tuples WHERE org_id = $1 AND deleted_at IS NULL AND status = 'ACTIVE' AND (expires_at_ms IS NULL OR expires_at_ms > $2)`,
  },
  FLOW_PASSWORD_HISTORY: {
    INSERT: `INSERT INTO auth_password_history (id, user_id, password_hash, created_at_ms) VALUES ($1, $2, $3, $4)`,
    GET_RECENT_HASHES: `SELECT password_hash FROM auth_password_history WHERE user_id = $1 AND deleted_at IS NULL ORDER BY created_at_ms DESC LIMIT $2`,
    PRUNE_OLD_ENTRIES: `
      UPDATE auth_password_history
      SET deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
      WHERE user_id = $1
        AND deleted_at IS NULL
        AND id NOT IN (
          SELECT id FROM auth_password_history
          WHERE user_id = $1 AND deleted_at IS NULL
          ORDER BY created_at_ms DESC
          LIMIT $2
        )
    `,
  },
  FLOW_PASSKEYS: {
    INSERT_CHALLENGE: `INSERT INTO auth_passkey_challenges (challenge_id, user_id, challenge, origin, rp_id, challenge_type, expires_at_ms, created_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    FIND_CHALLENGE: `SELECT challenge_id, user_id, challenge, origin, rp_id, challenge_type, expires_at_ms, created_at_ms FROM auth_passkey_challenges WHERE challenge_id = $1 AND expires_at_ms > $2 LIMIT 1`,
    CONSUME_CHALLENGE: `DELETE FROM auth_passkey_challenges WHERE challenge_id = $1`,
    INSERT_CREDENTIAL: `INSERT INTO auth_passkey_credentials (id, credential_id, user_id, org_id, public_key, counter, device_type, backed_up, transports, aaguid, friendly_name, created_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
    FIND_CREDENTIAL_BY_ID: `SELECT id, credential_id, user_id, org_id, public_key, counter, device_type, backed_up, transports, aaguid, friendly_name, created_at_ms, last_used_at_ms FROM auth_passkey_credentials WHERE credential_id = $1 AND deleted_at IS NULL LIMIT 1`,
    LIST_BY_USER_ID: `SELECT id, credential_id, user_id, org_id, public_key, counter, device_type, backed_up, transports, aaguid, friendly_name, created_at_ms, last_used_at_ms FROM auth_passkey_credentials WHERE user_id = $1 AND deleted_at IS NULL ORDER BY created_at_ms DESC`,
    UPDATE_COUNTER_AND_LAST_USED: `UPDATE auth_passkey_credentials SET counter = $2, last_used_at_ms = $3, updated_at = CURRENT_TIMESTAMP WHERE credential_id = $1 AND deleted_at IS NULL`,
    SOFT_DELETE_CREDENTIAL: `UPDATE auth_passkey_credentials SET deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL`,
  },
  FLOW_CUSTOM_ROLES: {
    INSERT_ROLE: `INSERT INTO auth_custom_roles (id, public_id, org_id, name, description, permission_mask, is_system_role, version, created_at_ms, updated_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
    FIND_ROLE_BY_ID: `SELECT id, public_id, org_id, name, description, permission_mask::text, is_system_role, version, created_at_ms, updated_at_ms FROM auth_custom_roles WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL LIMIT 1`,
    FIND_ROLE_BY_NAME: `SELECT id, public_id, org_id, name, description, permission_mask::text, is_system_role, version, created_at_ms, updated_at_ms FROM auth_custom_roles WHERE org_id = $1 AND name = $2 AND deleted_at IS NULL LIMIT 1`,
    LIST_ROLES_BY_ORG: `SELECT id, public_id, org_id, name, description, permission_mask::text, is_system_role, version, created_at_ms, updated_at_ms FROM auth_custom_roles WHERE org_id = $1 AND deleted_at IS NULL ORDER BY is_system_role DESC, name ASC`,
    UPDATE_ROLE: `UPDATE auth_custom_roles SET name = COALESCE($3, name), description = COALESCE($4, description), permission_mask = COALESCE($5, permission_mask), version = version + 1, updated_at_ms = $6 WHERE id = $1 AND org_id = $2 AND is_system_role = FALSE AND deleted_at IS NULL`,
    DELETE_ROLE: `UPDATE auth_custom_roles SET deleted_at = CURRENT_TIMESTAMP WHERE id = $1 AND org_id = $2 AND is_system_role = FALSE AND deleted_at IS NULL`,
    INSERT_USER_ROLE: `INSERT INTO auth_user_custom_roles (id, public_id, org_id, user_id, role_id, version, assigned_at_ms) VALUES ($1, $2, $3, $4, $5, 1, $6) ON CONFLICT (org_id, user_id, role_id) DO UPDATE SET deleted_at = NULL`,
    DELETE_USER_ROLES: `DELETE FROM auth_user_custom_roles WHERE org_id = $1 AND user_id = $2`,
    LIST_USER_ROLES: `
      SELECT r.id, r.public_id, r.org_id, r.name, r.description, r.permission_mask::text, r.is_system_role, r.version, r.created_at_ms, r.updated_at_ms
      FROM auth_custom_roles r
      INNER JOIN auth_user_custom_roles ur ON ur.role_id = r.id AND ur.org_id = r.org_id
      WHERE ur.org_id = $1 AND ur.user_id = $2 AND ur.deleted_at IS NULL AND r.deleted_at IS NULL
      ORDER BY r.name ASC
    `,
    INSERT_AUDIT_LOG: `INSERT INTO auth_role_audit_logs (id, org_id, actor_user_id, action, target_role_id, target_user_id, previous_mask, new_mask, reason, created_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
  },
  FLOW_MAGIC_LINKS: {
    INSERT_MAGIC_LINK: `INSERT INTO auth_magic_links (id, public_id, org_id, user_id, email, token_hash, redirect_url, request_ip, user_agent_hash, version, expires_at_ms, created_at_ms, updated_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
    FIND_BY_HASH: `SELECT id, public_id, org_id, user_id, email, token_hash, redirect_url, request_ip, user_agent_hash, consumed_at_ms, consumed_ip, superseded_at_ms, version, expires_at_ms, created_at_ms, updated_at_ms FROM auth_magic_links WHERE token_hash = $1 AND deleted_at IS NULL LIMIT 1`,
    SUPERSEDE_USER_PENDING: `UPDATE auth_magic_links SET superseded_at_ms = $3, version = version + 1, updated_at_ms = $3 WHERE org_id = $1 AND user_id = $2 AND consumed_at_ms IS NULL AND superseded_at_ms IS NULL AND deleted_at IS NULL`,
    CONSUME_LINK: `UPDATE auth_magic_links SET consumed_at_ms = $2, consumed_ip = $3, version = version + 1, updated_at_ms = $2 WHERE token_hash = $1 AND consumed_at_ms IS NULL AND superseded_at_ms IS NULL AND expires_at_ms > $2 AND deleted_at IS NULL`,
    COUNT_RECENT_BY_EMAIL: `SELECT COUNT(*)::int AS count FROM auth_magic_links WHERE email = $1 AND created_at_ms >= $2 AND deleted_at IS NULL`,
    COUNT_RECENT_BY_IP: `SELECT COUNT(*)::int AS count FROM auth_magic_links WHERE request_ip = $1 AND created_at_ms >= $2 AND deleted_at IS NULL`,
  },
  FLOW_WEBHOOKS: {
    INSERT_SUBSCRIPTION: `INSERT INTO auth_webhook_subscriptions (id, public_id, org_id, target_url, secret_hash, secret_prefix, subscribed_events, active, version, created_at_ms, updated_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
    FIND_SUBSCRIPTION_BY_ID: `SELECT id, public_id, org_id, target_url, secret_hash, secret_prefix, subscribed_events, active, version, created_at_ms, updated_at_ms FROM auth_webhook_subscriptions WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL LIMIT 1`,
    LIST_SUBSCRIPTIONS_BY_ORG: `SELECT id, public_id, org_id, target_url, secret_hash, secret_prefix, subscribed_events, active, version, created_at_ms, updated_at_ms FROM auth_webhook_subscriptions WHERE org_id = $1 AND deleted_at IS NULL ORDER BY created_at_ms DESC`,
    UPDATE_SUBSCRIPTION: `UPDATE auth_webhook_subscriptions SET target_url = COALESCE($3, target_url), subscribed_events = COALESCE($4, subscribed_events), active = COALESCE($5, active), version = version + 1, updated_at_ms = $6, updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL`,
    DELETE_SUBSCRIPTION: `UPDATE auth_webhook_subscriptions SET deleted_at = CURRENT_TIMESTAMP, active = FALSE, updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL`,
    INSERT_DELIVERY: `INSERT INTO auth_webhook_deliveries (id, public_id, subscription_id, org_id, event_type, nonce, response_status, execution_duration_ms, success, failure_reason, delivered_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
    LIST_DELIVERIES_BY_SUB: `SELECT id, public_id, subscription_id, org_id, event_type, nonce, response_status, execution_duration_ms, success, failure_reason, delivered_at_ms FROM auth_webhook_deliveries WHERE subscription_id = $1 AND org_id = $2 ORDER BY delivered_at_ms DESC LIMIT 100`,
  },
} as const;



