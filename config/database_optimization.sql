
-- PostgreSQL database optimizations for CyberOps

-- Add indexes to improve vulnerability search performance
CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vuln_cvss ON vulnerabilities(cvss_score);
CREATE INDEX IF NOT EXISTS idx_vuln_host ON vulnerabilities(host_id);
CREATE INDEX IF NOT EXISTS idx_vuln_name ON vulnerabilities(name);

-- Add index for faster scan results retrieval
CREATE INDEX IF NOT EXISTS idx_scan_target ON scan_results(target_id);
CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON scan_results(timestamp);
CREATE INDEX IF NOT EXISTS idx_scan_status ON scan_results(status);

-- Add index for improved API endpoint search
CREATE INDEX IF NOT EXISTS idx_endpoint_path ON api_endpoints(path);
CREATE INDEX IF NOT EXISTS idx_endpoint_method ON api_endpoints(method);
CREATE INDEX IF NOT EXISTS idx_endpoint_auth ON api_endpoints(auth_type);

-- Optimize vulnerability search query
CREATE OR REPLACE VIEW vw_critical_vulnerabilities AS
SELECT v.id, v.name, v.description, v.cvss_score, h.hostname, h.ip_address
FROM vulnerabilities v
JOIN hosts h ON v.host_id = h.id
WHERE v.severity = 'critical' OR v.cvss_score >= 9.0
ORDER BY v.cvss_score DESC;

-- Optimize host statistics query
CREATE OR REPLACE VIEW vw_host_vulnerability_summary AS
SELECT 
    h.id, 
    h.hostname, 
    h.ip_address,
    COUNT(v.id) AS total_vulnerabilities,
    SUM(CASE WHEN v.severity = 'critical' THEN 1 ELSE 0 END) AS critical_count,
    SUM(CASE WHEN v.severity = 'high' THEN 1 ELSE 0 END) AS high_count,
    SUM(CASE WHEN v.severity = 'medium' THEN 1 ELSE 0 END) AS medium_count,
    SUM(CASE WHEN v.severity = 'low' THEN 1 ELSE 0 END) AS low_count,
    AVG(v.cvss_score) AS avg_cvss
FROM hosts h
LEFT JOIN vulnerabilities v ON h.id = v.host_id
GROUP BY h.id, h.hostname, h.ip_address;

-- Add database maintenance functions
CREATE OR REPLACE FUNCTION maintenance_vacuum_analyze()
RETURNS void AS $$
BEGIN
    VACUUM ANALYZE;
END;
$$ LANGUAGE plpgsql;

-- Schedule regular database maintenance
-- Note: This requires pg_cron extension to be installed
-- CREATE EXTENSION IF NOT EXISTS pg_cron;
-- SELECT cron.schedule('0 1 * * *', 'SELECT maintenance_vacuum_analyze()');
