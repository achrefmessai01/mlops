-- Initialisation de la base de données MLOps
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Table pour les logs d'inférence
CREATE TABLE IF NOT EXISTS inference_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    user_ip INET,
    endpoint VARCHAR(255),
    model VARCHAR(100),
    prompt TEXT,
    prompt_length INTEGER,
    response TEXT,
    response_length INTEGER,
    latency REAL,
    security_analysis JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Table pour les alertes de sécurité
CREATE TABLE IF NOT EXISTS security_alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    user_ip INET,
    threat_type VARCHAR(100),
    risk_level VARCHAR(20),
    risk_score INTEGER,
    prompt_hash VARCHAR(64),
    threats_detected TEXT[],
    details JSONB,
    resolved BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Table pour les métriques KPI
CREATE TABLE IF NOT EXISTS kpi_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    date DATE DEFAULT CURRENT_DATE,
    total_requests INTEGER DEFAULT 0,
    unique_users INTEGER DEFAULT 0,
    avg_latency REAL DEFAULT 0,
    total_threats INTEGER DEFAULT 0,
    models_used JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(date)
);

-- Table pour les recommandations IA
CREATE TABLE IF NOT EXISTS ai_recommendations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    category VARCHAR(50),
    priority VARCHAR(20),
    title VARCHAR(255),
    description TEXT,
    action_items TEXT[],
    data_analyzed JSONB,
    implemented BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Index pour les performances
CREATE INDEX IF NOT EXISTS idx_inference_logs_timestamp ON inference_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_inference_logs_user_ip ON inference_logs(user_ip);
CREATE INDEX IF NOT EXISTS idx_inference_logs_model ON inference_logs(model);
CREATE INDEX IF NOT EXISTS idx_security_alerts_timestamp ON security_alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_security_alerts_risk_level ON security_alerts(risk_level);
CREATE INDEX IF NOT EXISTS idx_kpi_metrics_date ON kpi_metrics(date);

-- Vues pour les analyses
CREATE OR REPLACE VIEW daily_stats AS
SELECT 
    date,
    total_requests,
    unique_users,
    avg_latency,
    total_threats,
    models_used
FROM kpi_metrics
ORDER BY date DESC;

CREATE OR REPLACE VIEW security_summary AS
SELECT 
    DATE(timestamp) as date,
    COUNT(*) as total_alerts,
    COUNT(*) FILTER (WHERE risk_level = 'CRITICAL') as critical_alerts,
    COUNT(*) FILTER (WHERE risk_level = 'HIGH') as high_alerts,
    COUNT(*) FILTER (WHERE risk_level = 'MEDIUM') as medium_alerts,
    COUNT(*) FILTER (WHERE risk_level = 'LOW') as low_alerts
FROM security_alerts
GROUP BY DATE(timestamp)
ORDER BY date DESC;

-- Permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO mlops;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO mlops;
