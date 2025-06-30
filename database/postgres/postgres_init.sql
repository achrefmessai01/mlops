-- =====================================
-- MLOps Platform - Complete Database Schema
-- =====================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- =====================================
-- CORE INFERENCE TRACKING
-- =====================================

-- Enhanced table for inference logs with security analysis
CREATE TABLE IF NOT EXISTS inference_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    user_id VARCHAR(255),
    user_ip INET,
    session_id VARCHAR(255),
    endpoint VARCHAR(255),
    model VARCHAR(100),
    model_provider VARCHAR(50), -- OpenAI, OpenRouter, etc.
    prompt TEXT,
    prompt_length INTEGER,
    prompt_hash VARCHAR(64),
    response TEXT,
    response_length INTEGER,
    latency_ms REAL,
    tokens_input INTEGER,
    tokens_output INTEGER,
    cost_input DECIMAL(10,6),
    cost_output DECIMAL(10,6),
    total_cost DECIMAL(10,6),
    security_analysis JSONB,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================================
-- ADVANCED SECURITY SYSTEM
-- =====================================

-- Enhanced security alerts with detailed threat analysis
CREATE TABLE IF NOT EXISTS security_alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    user_id VARCHAR(255),
    user_ip INET,
    session_id VARCHAR(255),
    threat_type VARCHAR(100),
    threat_category VARCHAR(50), -- injection, jailbreak, extraction, etc.
    risk_level VARCHAR(20),
    risk_score INTEGER,
    confidence_score DECIMAL(3,2), -- 0.00 to 1.00
    prompt_hash VARCHAR(64),
    threats_detected TEXT[],
    attack_patterns TEXT[],
    blocked BOOLEAN DEFAULT FALSE,
    details JSONB,
    resolved BOOLEAN DEFAULT FALSE,
    resolved_by VARCHAR(255),
    resolved_at TIMESTAMP WITH TIME ZONE,
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- User behavior tracking for advanced analytics
CREATE TABLE IF NOT EXISTS user_behavior (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(255) NOT NULL,
    date DATE DEFAULT CURRENT_DATE,
    total_requests INTEGER DEFAULT 0,
    total_tokens INTEGER DEFAULT 0,
    total_cost DECIMAL(10,6) DEFAULT 0,
    avg_latency_ms REAL DEFAULT 0,
    security_incidents INTEGER DEFAULT 0,
    risk_score INTEGER DEFAULT 0,
    behavior_patterns JSONB,
    anomalies_detected TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, date)
);

-- =====================================
-- LLM JUDGE SYSTEM TABLES
-- =====================================

-- Judge analysis results
CREATE TABLE IF NOT EXISTS judge_analysis (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    analysis_type VARCHAR(50), -- user_behavior, system_health, security_audit
    analysis_period_hours INTEGER,
    user_id VARCHAR(255), -- null for system-wide analysis
    risk_level VARCHAR(20),
    risk_score INTEGER,
    confidence_score DECIMAL(3,2),
    analysis_data JSONB NOT NULL,
    recommendations TEXT[],
    action_items JSONB,
    ai_model_used VARCHAR(50),
    processing_time_ms INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Judge recommendations with tracking
CREATE TABLE IF NOT EXISTS judge_recommendations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    analysis_id UUID REFERENCES judge_analysis(id),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    category VARCHAR(50), -- security, performance, cost, business
    priority VARCHAR(20), -- LOW, MEDIUM, HIGH, CRITICAL
    type VARCHAR(50), -- USER_ACTION, SYSTEM_CONFIG, SECURITY_POLICY, etc.
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    action_items TEXT[],
    estimated_impact VARCHAR(20), -- LOW, MEDIUM, HIGH
    effort_required VARCHAR(20), -- LOW, MEDIUM, HIGH
    roi_estimate DECIMAL(5,2), -- estimated ROI percentage
    data_analyzed JSONB,
    implemented BOOLEAN DEFAULT FALSE,
    implemented_by VARCHAR(255),
    implemented_at TIMESTAMP WITH TIME ZONE,
    effectiveness_score INTEGER, -- 1-10 after implementation
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================================
-- PERFORMANCE & KPI METRICS
-- =====================================

-- Enhanced KPI metrics with detailed breakdown
CREATE TABLE IF NOT EXISTS kpi_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    date DATE DEFAULT CURRENT_DATE,
    hour INTEGER, -- 0-23 for hourly metrics
    total_requests INTEGER DEFAULT 0,
    unique_users INTEGER DEFAULT 0,
    unique_sessions INTEGER DEFAULT 0,
    avg_latency_ms REAL DEFAULT 0,
    p95_latency_ms REAL DEFAULT 0,
    p99_latency_ms REAL DEFAULT 0,
    total_tokens INTEGER DEFAULT 0,
    total_cost DECIMAL(10,6) DEFAULT 0,
    total_threats INTEGER DEFAULT 0,
    blocked_requests INTEGER DEFAULT 0,
    error_rate DECIMAL(5,4) DEFAULT 0,
    models_used JSONB,
    model_performance JSONB,
    security_summary JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(date, hour)
);

-- Model performance tracking
CREATE TABLE IF NOT EXISTS model_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    date DATE DEFAULT CURRENT_DATE,
    model VARCHAR(100) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    total_requests INTEGER DEFAULT 0,
    total_tokens_input INTEGER DEFAULT 0,
    total_tokens_output INTEGER DEFAULT 0,
    total_cost DECIMAL(10,6) DEFAULT 0,
    avg_latency_ms REAL DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    error_rate DECIMAL(5,4) DEFAULT 0,
    quality_score DECIMAL(3,2), -- user satisfaction metric
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(date, model, provider)
);

-- =====================================
-- SYSTEM MONITORING
-- =====================================

-- System health metrics
CREATE TABLE IF NOT EXISTS system_health (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    component VARCHAR(50), -- api, database, cache, langfuse, judge
    status VARCHAR(20), -- healthy, warning, critical, down
    response_time_ms INTEGER,
    cpu_usage DECIMAL(5,2),
    memory_usage DECIMAL(5,2),
    disk_usage DECIMAL(5,2),
    error_count INTEGER DEFAULT 0,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Event log for system events
CREATE TABLE IF NOT EXISTS system_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    event_type VARCHAR(100),
    severity VARCHAR(20), -- INFO, WARNING, ERROR, CRITICAL
    component VARCHAR(50),
    user_id VARCHAR(255),
    message TEXT NOT NULL,
    details JSONB,
    resolved BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================================
-- OPTIMIZED INDEXES
-- =====================================

-- Inference logs indexes
CREATE INDEX IF NOT EXISTS idx_inference_logs_timestamp ON inference_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_inference_logs_user_id ON inference_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_inference_logs_model ON inference_logs(model);
CREATE INDEX IF NOT EXISTS idx_inference_logs_cost ON inference_logs(total_cost DESC);
CREATE INDEX IF NOT EXISTS idx_inference_logs_latency ON inference_logs(latency_ms);
CREATE INDEX IF NOT EXISTS idx_inference_logs_session ON inference_logs(session_id);

-- Security alerts indexes
CREATE INDEX IF NOT EXISTS idx_security_alerts_timestamp ON security_alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_alerts_user_id ON security_alerts(user_id);
CREATE INDEX IF NOT EXISTS idx_security_alerts_risk_level ON security_alerts(risk_level);
CREATE INDEX IF NOT EXISTS idx_security_alerts_threat_type ON security_alerts(threat_type);
CREATE INDEX IF NOT EXISTS idx_security_alerts_resolved ON security_alerts(resolved);

-- User behavior indexes
CREATE INDEX IF NOT EXISTS idx_user_behavior_user_date ON user_behavior(user_id, date DESC);
CREATE INDEX IF NOT EXISTS idx_user_behavior_risk_score ON user_behavior(risk_score DESC);

-- Judge analysis indexes
CREATE INDEX IF NOT EXISTS idx_judge_analysis_timestamp ON judge_analysis(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_judge_analysis_type ON judge_analysis(analysis_type);
CREATE INDEX IF NOT EXISTS idx_judge_analysis_user_id ON judge_analysis(user_id);
CREATE INDEX IF NOT EXISTS idx_judge_analysis_risk_level ON judge_analysis(risk_level);

-- KPI metrics indexes
CREATE INDEX IF NOT EXISTS idx_kpi_metrics_date ON kpi_metrics(date DESC);
CREATE INDEX IF NOT EXISTS idx_kpi_metrics_hour ON kpi_metrics(date, hour);

-- Model metrics indexes
CREATE INDEX IF NOT EXISTS idx_model_metrics_date_model ON model_metrics(date DESC, model);
CREATE INDEX IF NOT EXISTS idx_model_metrics_cost ON model_metrics(total_cost DESC);

-- System health indexes
CREATE INDEX IF NOT EXISTS idx_system_health_timestamp ON system_health(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_system_health_component ON system_health(component, status);

-- System events indexes
CREATE INDEX IF NOT EXISTS idx_system_events_timestamp ON system_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_system_events_severity ON system_events(severity);
CREATE INDEX IF NOT EXISTS idx_system_events_component ON system_events(component);

-- =====================================
-- ANALYTICAL VIEWS
-- =====================================

-- Daily statistics view
CREATE OR REPLACE VIEW daily_stats AS
SELECT 
    date,
    SUM(total_requests) as total_requests,
    MAX(unique_users) as unique_users,
    AVG(avg_latency_ms) as avg_latency_ms,
    SUM(total_threats) as total_threats,
    SUM(total_cost) as total_cost,
    AVG(error_rate) as avg_error_rate,
    models_used
FROM kpi_metrics
WHERE hour IS NULL OR hour = 0 -- Daily aggregates
GROUP BY date, models_used
ORDER BY date DESC;

-- Security dashboard view
CREATE OR REPLACE VIEW security_dashboard AS
SELECT 
    DATE(timestamp) as date,
    COUNT(*) as total_alerts,
    COUNT(*) FILTER (WHERE risk_level = 'CRITICAL') as critical_alerts,
    COUNT(*) FILTER (WHERE risk_level = 'HIGH') as high_alerts,
    COUNT(*) FILTER (WHERE risk_level = 'MEDIUM') as medium_alerts,
    COUNT(*) FILTER (WHERE risk_level = 'LOW') as low_alerts,
    COUNT(*) FILTER (WHERE blocked = true) as blocked_attacks,
    COUNT(DISTINCT user_id) as affected_users,
    array_agg(DISTINCT threat_type) as threat_types
FROM security_alerts
GROUP BY DATE(timestamp)
ORDER BY date DESC;

-- User risk profile view
CREATE OR REPLACE VIEW user_risk_profiles AS
SELECT 
    ub.user_id,
    ub.date,
    ub.total_requests,
    ub.total_cost,
    ub.risk_score,
    ub.security_incidents,
    COALESCE(sa.recent_threats, 0) as recent_threats,
    CASE 
        WHEN ub.risk_score >= 15 THEN 'CRITICAL'
        WHEN ub.risk_score >= 10 THEN 'HIGH'
        WHEN ub.risk_score >= 5 THEN 'MEDIUM'
        ELSE 'LOW'
    END as risk_level
FROM user_behavior ub
LEFT JOIN (
    SELECT 
        user_id, 
        COUNT(*) as recent_threats
    FROM security_alerts 
    WHERE timestamp >= NOW() - INTERVAL '24 hours'
    GROUP BY user_id
) sa ON ub.user_id = sa.user_id
WHERE ub.date >= CURRENT_DATE - INTERVAL '7 days'
ORDER BY ub.risk_score DESC, ub.total_requests DESC;

-- Model performance comparison
CREATE OR REPLACE VIEW model_performance_comparison AS
SELECT 
    model,
    provider,
    AVG(total_cost / NULLIF(total_requests, 0)) as avg_cost_per_request,
    AVG(avg_latency_ms) as avg_latency_ms,
    AVG(error_rate) as avg_error_rate,
    AVG(quality_score) as avg_quality_score,
    SUM(total_requests) as total_requests_7d
FROM model_metrics
WHERE date >= CURRENT_DATE - INTERVAL '7 days'
GROUP BY model, provider
ORDER BY avg_quality_score DESC, avg_cost_per_request ASC;

-- System health summary
CREATE OR REPLACE VIEW system_health_summary AS
SELECT 
    component,
    status,
    COUNT(*) as status_count,
    AVG(response_time_ms) as avg_response_time_ms,
    MAX(timestamp) as last_check
FROM system_health
WHERE timestamp >= NOW() - INTERVAL '1 hour'
GROUP BY component, status
ORDER BY component, 
    CASE status 
        WHEN 'critical' THEN 1 
        WHEN 'warning' THEN 2 
        WHEN 'healthy' THEN 3 
        ELSE 4 
    END;

-- Judge insights summary
CREATE OR REPLACE VIEW judge_insights_summary AS
SELECT 
    DATE(timestamp) as date,
    analysis_type,
    COUNT(*) as total_analyses,
    COUNT(*) FILTER (WHERE risk_level = 'CRITICAL') as critical_findings,
    COUNT(*) FILTER (WHERE risk_level = 'HIGH') as high_risk_findings,
    AVG(confidence_score) as avg_confidence,
    COUNT(DISTINCT user_id) as users_analyzed
FROM judge_analysis
WHERE timestamp >= NOW() - INTERVAL '7 days'
GROUP BY DATE(timestamp), analysis_type
ORDER BY date DESC, analysis_type;

-- =====================================
-- FUNCTIONS FOR DATA MANAGEMENT
-- =====================================

-- Function to clean old data
CREATE OR REPLACE FUNCTION cleanup_old_data(days_to_keep INTEGER DEFAULT 90)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER := 0;
    temp_count INTEGER;
BEGIN
    -- Clean inference logs older than specified days
    DELETE FROM inference_logs WHERE created_at < NOW() - INTERVAL '1 day' * days_to_keep;
    GET DIAGNOSTICS temp_count = ROW_COUNT;
    deleted_count := deleted_count + temp_count;
    
    -- Clean resolved security alerts older than specified days  
    DELETE FROM security_alerts WHERE resolved = true AND created_at < NOW() - INTERVAL '1 day' * days_to_keep;
    GET DIAGNOSTICS temp_count = ROW_COUNT;
    deleted_count := deleted_count + temp_count;
    
    -- Clean old system health records (keep only 30 days)
    DELETE FROM system_health WHERE created_at < NOW() - INTERVAL '30 days';
    GET DIAGNOSTICS temp_count = ROW_COUNT;
    deleted_count := deleted_count + temp_count;
    
    -- Clean old system events (keep based on severity)
    DELETE FROM system_events WHERE 
        (severity IN ('INFO', 'WARNING') AND created_at < NOW() - INTERVAL '30 days') OR
        (severity = 'ERROR' AND created_at < NOW() - INTERVAL '60 days') OR
        (severity = 'CRITICAL' AND created_at < NOW() - INTERVAL '1 day' * days_to_keep);
    GET DIAGNOSTICS temp_count = ROW_COUNT;
    deleted_count := deleted_count + temp_count;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to update user behavior metrics
CREATE OR REPLACE FUNCTION update_user_behavior_daily()
RETURNS VOID AS $$
BEGIN
    INSERT INTO user_behavior (
        user_id, 
        date, 
        total_requests, 
        total_tokens, 
        total_cost, 
        avg_latency_ms, 
        security_incidents
    )
    SELECT 
        user_id,
        CURRENT_DATE,
        COUNT(*) as total_requests,
        SUM(tokens_input + tokens_output) as total_tokens,
        SUM(total_cost) as total_cost,
        AVG(latency_ms) as avg_latency_ms,
        COUNT(*) FILTER (WHERE (security_analysis->>'risk_level')::text IN ('HIGH', 'CRITICAL')) as security_incidents
    FROM inference_logs
    WHERE DATE(timestamp) = CURRENT_DATE
        AND user_id IS NOT NULL
    GROUP BY user_id
    ON CONFLICT (user_id, date) 
    DO UPDATE SET
        total_requests = EXCLUDED.total_requests,
        total_tokens = EXCLUDED.total_tokens,
        total_cost = EXCLUDED.total_cost,
        avg_latency_ms = EXCLUDED.avg_latency_ms,
        security_incidents = EXCLUDED.security_incidents,
        updated_at = NOW();
END;
$$ LANGUAGE plpgsql;

-- =====================================
-- PERMISSIONS & SECURITY
-- =====================================

-- Grant permissions to mlops user
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO mlops;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO mlops;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO mlops;

-- Create read-only user for analytics
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'mlops_reader') THEN
        CREATE ROLE mlops_reader WITH LOGIN PASSWORD 'mlops_reader_pass';
    END IF;
END
$$;

GRANT CONNECT ON DATABASE mlops TO mlops_reader;
GRANT USAGE ON SCHEMA public TO mlops_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO mlops_reader;

-- =====================================
-- INITIAL DATA & CONFIGURATION
-- =====================================

-- Insert initial system health check
INSERT INTO system_health (component, status, response_time_ms, details) VALUES
('database', 'healthy', 5, '{"version": "15", "connections": 10}'),
('api', 'healthy', 15, '{"version": "1.0.0", "uptime": "0 minutes"}')
ON CONFLICT DO NOTHING;

-- Insert initial system event
INSERT INTO system_events (event_type, severity, component, message, details) VALUES
('database_initialized', 'INFO', 'database', 'MLOps database schema initialized successfully', 
 '{"tables_created": 12, "indexes_created": 25, "views_created": 6}')
ON CONFLICT DO NOTHING;

-- =====================================
-- COMPLETION MESSAGE
-- =====================================

DO $$
BEGIN
    RAISE NOTICE '=====================================';
    RAISE NOTICE 'MLOps Database Schema Initialized Successfully!';
    RAISE NOTICE '=====================================';
    RAISE NOTICE 'Tables created: %', (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public');
    RAISE NOTICE 'Indexes created: %', (SELECT COUNT(*) FROM pg_indexes WHERE schemaname = 'public');
    RAISE NOTICE 'Views created: %', (SELECT COUNT(*) FROM information_schema.views WHERE table_schema = 'public');
    RAISE NOTICE 'Functions created: %', (SELECT COUNT(*) FROM information_schema.routines WHERE routine_schema = 'public');
    RAISE NOTICE '=====================================';
END
$$;