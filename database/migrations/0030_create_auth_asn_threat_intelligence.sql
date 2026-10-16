CREATE TABLE IF NOT EXISTS auth_asn_reputation (
    asn VARCHAR(32) NOT NULL,
    organization_name VARCHAR(255) NOT NULL,
    threat_category VARCHAR(32) NOT NULL DEFAULT 'RESIDENTIAL',
    threat_score INT NOT NULL DEFAULT 0,
    is_blocked BOOLEAN NOT NULL DEFAULT FALSE,
    blocked_reason VARCHAR(255) NULL,
    velocity_limit_per_minute INT NOT NULL DEFAULT 200,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT auth_asn_reputation_pk PRIMARY KEY (asn),
    CONSTRAINT auth_asn_threat_score_ck CHECK (threat_score >= 0 AND threat_score <= 100),
    CONSTRAINT auth_asn_category_ck CHECK (threat_category IN ('RESIDENTIAL', 'DATACENTER', 'VPN_PROXY', 'TOR_EXIT', 'BULLETPROOF_HOSTING')),
    CONSTRAINT auth_asn_velocity_limit_ck CHECK (velocity_limit_per_minute > 0),
    CONSTRAINT auth_asn_block_state_ck CHECK (
        (is_blocked = FALSE AND blocked_reason IS NULL) OR
        (is_blocked = TRUE AND blocked_reason IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_auth_asn_reputation_threat ON auth_asn_reputation(threat_score, is_blocked);
CREATE INDEX IF NOT EXISTS idx_auth_asn_reputation_category ON auth_asn_reputation(threat_category);

INSERT INTO auth_asn_reputation (asn, organization_name, threat_category, threat_score, is_blocked, blocked_reason, velocity_limit_per_minute)
VALUES
    ('AS16509', 'Amazon.com, Inc.', 'DATACENTER', 60, FALSE, NULL, 50),
    ('AS15169', 'Google LLC', 'DATACENTER', 50, FALSE, NULL, 60),
    ('AS8075', 'Microsoft Corporation', 'DATACENTER', 50, FALSE, NULL, 60),
    ('AS14061', 'DigitalOcean, LLC', 'DATACENTER', 70, FALSE, NULL, 40),
    ('AS24940', 'Hetzner Online GmbH', 'DATACENTER', 75, FALSE, NULL, 30),
    ('AS16276', 'OVH SAS', 'DATACENTER', 75, FALSE, NULL, 30),
    ('AS99999', 'Bulletproof Host Network', 'BULLETPROOF_HOSTING', 95, TRUE, 'Active botnet C2 network confirmed by threat intel', 10)
ON CONFLICT (asn) DO NOTHING;
