-- ============================================================================
-- Optimesh Config Review Studio — Initial Database Schema
-- PostgreSQL (Supabase) | Version 1
-- ============================================================================

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- ORGANIZATIONS
-- ============================================================================
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    settings JSONB NOT NULL DEFAULT '{}',
    tier TEXT NOT NULL DEFAULT 'startup' CHECK (tier IN ('startup', 'mid_market', 'enterprise')),
    trial_ends_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- USERS (extends Supabase auth.users)
-- ============================================================================
CREATE TABLE users (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    display_name TEXT,
    role TEXT NOT NULL DEFAULT 'engineer' CHECK (role IN ('admin', 'engineer', 'auditor')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_org ON users(org_id);

-- ============================================================================
-- API KEYS
-- ============================================================================
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash TEXT NOT NULL,  -- SHA-256 of the key (never store plaintext)
    name TEXT NOT NULL,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_org ON api_keys(org_id);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);

-- ============================================================================
-- REVIEWS
-- ============================================================================
CREATE TABLE reviews (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    config_hash TEXT NOT NULL,  -- SHA-256 of submitted config
    vendor TEXT NOT NULL,
    os_version TEXT,
    hostname TEXT,
    snippet_mode BOOLEAN NOT NULL DEFAULT FALSE,
    quick_pass BOOLEAN NOT NULL DEFAULT FALSE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'complete', 'failed')),
    risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_grade TEXT,
    pass_fail BOOLEAN,
    summary JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_reviews_org ON reviews(org_id);
CREATE INDEX idx_reviews_user ON reviews(user_id);
CREATE INDEX idx_reviews_hostname ON reviews(org_id, hostname);
CREATE INDEX idx_reviews_created ON reviews(created_at DESC);

-- ============================================================================
-- FINDINGS
-- ============================================================================
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    review_id UUID NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
    line_start INTEGER NOT NULL,
    line_end INTEGER NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'warning', 'info')),
    category TEXT NOT NULL CHECK (category IN ('syntax', 'security', 'compliance', 'best_practice')),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    remediation TEXT NOT NULL DEFAULT '',
    rollback TEXT NOT NULL DEFAULT '',
    reference_url TEXT,
    compliance_tags TEXT[] NOT NULL DEFAULT '{}',
    config_context TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_findings_review ON findings(review_id);
CREATE INDEX idx_findings_severity ON findings(review_id, severity);

-- ============================================================================
-- REPORTS (stored in Supabase Storage, metadata here)
-- ============================================================================
CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    review_id UUID NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
    format TEXT NOT NULL CHECK (format IN ('pdf', 'json')),
    storage_path TEXT NOT NULL,  -- Path in Supabase Storage
    template_version_id UUID,
    config_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_reports_review ON reports(review_id);

-- ============================================================================
-- TEMPLATES
-- ============================================================================
CREATE TABLE templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,  -- NULL = starter template
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    is_starter BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_templates_org ON templates(org_id);

CREATE TABLE template_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    template_id UUID NOT NULL REFERENCES templates(id) ON DELETE CASCADE,
    version_num INTEGER NOT NULL,
    rules JSONB NOT NULL,  -- Array of TemplateRule objects
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    UNIQUE (template_id, version_num)
);

CREATE INDEX idx_template_versions_template ON template_versions(template_id);

-- ============================================================================
-- DEVICE CONFIGS (opt-in retention)
-- ============================================================================
CREATE TABLE device_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    vendor TEXT NOT NULL,
    config_text_encrypted BYTEA,  -- AES-256 encrypted config
    config_type TEXT NOT NULL DEFAULT 'running' CHECK (config_type IN ('running', 'startup')),
    review_id UUID REFERENCES reviews(id),
    retained BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_device_configs_org_host ON device_configs(org_id, hostname);
CREATE INDEX idx_device_configs_created ON device_configs(created_at DESC);

-- ============================================================================
-- WEBHOOKS
-- ============================================================================
CREATE TABLE webhooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    events TEXT[] NOT NULL DEFAULT '{review.complete}',
    secret TEXT NOT NULL,  -- For webhook signature verification
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhooks_org ON webhooks(org_id);

-- ============================================================================
-- NL QUERY HISTORY
-- ============================================================================
CREATE TABLE query_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    review_id UUID NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    question TEXT NOT NULL,
    answer TEXT NOT NULL,
    line_references INTEGER[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_query_history_review ON query_history(review_id);

-- ============================================================================
-- ROW LEVEL SECURITY
-- ============================================================================
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE reviews ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE template_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE query_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;

-- Users can only see their own org's data
CREATE POLICY org_isolation_users ON users
    FOR ALL USING (org_id = (SELECT org_id FROM users WHERE id = auth.uid()));

CREATE POLICY org_isolation_reviews ON reviews
    FOR ALL USING (org_id = (SELECT org_id FROM users WHERE id = auth.uid()));

CREATE POLICY org_isolation_findings ON findings
    FOR ALL USING (review_id IN (
        SELECT id FROM reviews WHERE org_id = (SELECT org_id FROM users WHERE id = auth.uid())
    ));

CREATE POLICY org_isolation_reports ON reports
    FOR ALL USING (review_id IN (
        SELECT id FROM reviews WHERE org_id = (SELECT org_id FROM users WHERE id = auth.uid())
    ));

CREATE POLICY org_isolation_templates ON templates
    FOR ALL USING (
        is_starter = TRUE  -- Starter templates visible to all
        OR org_id = (SELECT org_id FROM users WHERE id = auth.uid())
    );

CREATE POLICY org_isolation_template_versions ON template_versions
    FOR ALL USING (template_id IN (
        SELECT id FROM templates WHERE is_starter = TRUE
        OR org_id = (SELECT org_id FROM users WHERE id = auth.uid())
    ));

CREATE POLICY org_isolation_device_configs ON device_configs
    FOR ALL USING (org_id = (SELECT org_id FROM users WHERE id = auth.uid()));

CREATE POLICY org_isolation_webhooks ON webhooks
    FOR ALL USING (org_id = (SELECT org_id FROM users WHERE id = auth.uid()));

CREATE POLICY org_isolation_query_history ON query_history
    FOR ALL USING (review_id IN (
        SELECT id FROM reviews WHERE org_id = (SELECT org_id FROM users WHERE id = auth.uid())
    ));

CREATE POLICY org_isolation_api_keys ON api_keys
    FOR ALL USING (org_id = (SELECT org_id FROM users WHERE id = auth.uid()));

-- Organizations: users can see their own org
CREATE POLICY org_self ON organizations
    FOR ALL USING (id = (SELECT org_id FROM users WHERE id = auth.uid()));

-- ============================================================================
-- FUNCTIONS
-- ============================================================================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_organizations_updated
    BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trigger_users_updated
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trigger_templates_updated
    BEFORE UPDATE ON templates
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
