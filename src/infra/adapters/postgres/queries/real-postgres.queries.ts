import { AUTH_QUERIES } from '../../../../features/auth/queries/auth.queries';

export const REAL_POSTGRES_QUERIES = {
  ...AUTH_QUERIES,

  SCIM: {
    INSERT_TOKEN: `INSERT INTO auth_scim_tokens (id, org_id, token_hash, description, status, created_at_ms, expires_at_ms, last_used_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    FIND_TOKEN_BY_HASH: `SELECT id, org_id, token_hash, description, status, created_at_ms, expires_at_ms, last_used_at_ms FROM auth_scim_tokens WHERE token_hash = $1 AND deleted_at IS NULL AND status = 'ACTIVE'`,
    INSERT_MAPPING: `INSERT INTO auth_scim_external_mappings (id, org_id, resource_type, internal_id, external_id, created_at_ms, updated_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (org_id, resource_type, external_id) DO UPDATE SET internal_id = $4, updated_at_ms = $7`,
    FIND_MAPPING: `SELECT internal_id FROM auth_scim_external_mappings WHERE org_id = $1 AND resource_type = $2 AND external_id = $3`,
    INSERT_GROUP: `INSERT INTO auth_groups (id, org_id, display_name, created_at_ms, updated_at_ms) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO UPDATE SET display_name = $3, updated_at_ms = $5`,
    FIND_GROUP_BY_ID: `SELECT g.id, g.display_name, g.created_at_ms, g.updated_at_ms, m.external_id FROM auth_groups g LEFT JOIN auth_scim_external_mappings m ON m.internal_id = g.id AND m.resource_type = 'group' WHERE g.id = $1 AND g.org_id = $2 AND g.deleted_at IS NULL`,
    LIST_GROUP_MEMBERS: `SELECT gm.user_id, u.name, u.email FROM auth_group_members gm JOIN auth_users u ON u.id = gm.user_id WHERE gm.group_id = $1`,
    LIST_GROUPS: `SELECT id FROM auth_groups WHERE org_id = $1 AND deleted_at IS NULL ORDER BY created_at_ms ASC`,
    DELETE_GROUP: `UPDATE auth_groups SET deleted_at = CURRENT_TIMESTAMP WHERE id = $1 AND org_id = $2`,
    ADD_GROUP_MEMBER: `INSERT INTO auth_group_members (id, group_id, user_id, added_at_ms) VALUES ($1, $2, $3, $4) ON CONFLICT (group_id, user_id) DO NOTHING`,
    REMOVE_GROUP_MEMBER: `DELETE FROM auth_group_members WHERE group_id = $1 AND user_id = $2`,
  },

  OAUTH: {
    INSERT_CLIENT: `INSERT INTO auth_oauth_clients (id, org_id, client_name, client_secret_hash, redirect_uris, grant_types, response_types, client_type, status, created_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT (id) DO UPDATE SET client_name = $3, redirect_uris = $5, status = $9`,
    FIND_CLIENT_BY_ID: `SELECT id, org_id, client_name, client_secret_hash, redirect_uris, grant_types, response_types, client_type, status, created_at_ms FROM auth_oauth_clients WHERE id = $1 AND deleted_at IS NULL AND status = 'ACTIVE'`,
    INSERT_AUTH_CODE: `INSERT INTO auth_oauth_codes (code, client_id, user_id, org_id, redirect_uri, code_challenge, code_challenge_method, scope, used, expires_at_ms, created_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
    FIND_AUTH_CODE: `SELECT code, client_id, user_id, org_id, redirect_uri, code_challenge, code_challenge_method, scope, used, expires_at_ms, created_at_ms FROM auth_oauth_codes WHERE code = $1`,
    CONSUME_AUTH_CODE: `UPDATE auth_oauth_codes SET used = TRUE WHERE code = $1`,
    INSERT_SIGNING_KEY: `INSERT INTO auth_signing_keys (kid, kty, alg, use, public_key_pem, private_key_pem, status, created_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (kid) DO NOTHING`,
    GET_ACTIVE_SIGNING_KEY: `SELECT kid, kty, alg, use, public_key_pem, private_key_pem, status, created_at_ms FROM auth_signing_keys WHERE status = 'ACTIVE' ORDER BY created_at_ms DESC LIMIT 1`,
  },

  SAML: {
    UPSERT_PROVIDER: `
      INSERT INTO auth_saml_providers (
        id, org_id, idp_entity_id, idp_sso_url, idp_certificate_pem, sp_entity_id, attribute_mapping, status, created_at_ms
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      ON CONFLICT (id) DO UPDATE SET
        idp_entity_id = EXCLUDED.idp_entity_id,
        idp_sso_url = EXCLUDED.idp_sso_url,
        idp_certificate_pem = EXCLUDED.idp_certificate_pem,
        sp_entity_id = EXCLUDED.sp_entity_id,
        attribute_mapping = EXCLUDED.attribute_mapping,
        status = EXCLUDED.status,
        updated_at = CURRENT_TIMESTAMP
    `,
    FIND_PROVIDER_BY_ORG_ID: `SELECT * FROM auth_saml_providers WHERE org_id = $1 AND deleted_at IS NULL AND status = 'ACTIVE' LIMIT 1`,
    FIND_PROVIDER_BY_ID: `SELECT * FROM auth_saml_providers WHERE id = $1 AND deleted_at IS NULL LIMIT 1`,
    LIST_PROVIDERS_BY_ORG_ID: `SELECT * FROM auth_saml_providers WHERE org_id = $1 AND deleted_at IS NULL ORDER BY created_at_ms DESC`,
    INSERT_REQUEST: `
      INSERT INTO auth_saml_requests (relay_state, org_id, provider_id, request_id, return_url, expires_at_ms, created_at_ms)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
    `,
    CONSUME_REQUEST: `DELETE FROM auth_saml_requests WHERE relay_state = $1 RETURNING *`,
    RECORD_ASSERTION_ID: `INSERT INTO auth_saml_assertion_replay (assertion_id, expires_at_ms, created_at_ms) VALUES ($1, $2, $3)`,
  },
} as const;

export { AUTH_QUERIES };
