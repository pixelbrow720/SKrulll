
// Neo4j database optimizations for SKrulll
// Optimized version based on recommendations

//=============================================================================
// SCHEMA OPTIMIZATIONS
//=============================================================================

// Create constraints for unique identifiers
CREATE CONSTRAINT host_ip IF NOT EXISTS FOR (h:Host) REQUIRE h.ip IS UNIQUE;
CREATE CONSTRAINT vuln_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE;
CREATE CONSTRAINT service_name_port IF NOT EXISTS FOR (s:Service) REQUIRE (s.name, s.port) IS NODE KEY;
CREATE CONSTRAINT network_cidr IF NOT EXISTS FOR (n:Network) REQUIRE n.cidr IS UNIQUE;
CREATE CONSTRAINT scan_id IF NOT EXISTS FOR (s:Scan) REQUIRE s.id IS UNIQUE;

// Create indexes for performance improvements
// Host indexes
CREATE INDEX host_hostname_idx IF NOT EXISTS FOR (h:Host) ON (h.hostname);
CREATE INDEX host_last_seen_idx IF NOT EXISTS FOR (h:Host) ON (h.last_seen);
CREATE INDEX host_os_idx IF NOT EXISTS FOR (h:Host) ON (h.os);

// Vulnerability indexes
CREATE INDEX vuln_severity_idx IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity);
CREATE INDEX vuln_cvss_idx IF NOT EXISTS FOR (v:Vulnerability) ON (v.cvss);
CREATE INDEX vuln_published_idx IF NOT EXISTS FOR (v:Vulnerability) ON (v.published_date);
CREATE INDEX vuln_name_idx IF NOT EXISTS FOR (v:Vulnerability) ON (v.name);

// Service indexes
CREATE INDEX service_version_idx IF NOT EXISTS FOR (s:Service) ON (s.version);
CREATE INDEX service_name_idx IF NOT EXISTS FOR (s:Service) ON (s.name);

// Network indexes
CREATE INDEX network_scan_time_idx IF NOT EXISTS FOR (n:Network) ON (n.scan_time);
CREATE INDEX network_last_updated_idx IF NOT EXISTS FOR (n:Network) ON (n.last_updated);

// Scan indexes
CREATE INDEX scan_time_idx IF NOT EXISTS FOR (s:Scan) ON (s.time);

//=============================================================================
// QUERY OPTIMIZATIONS
//=============================================================================

// Optimize attack path query using APOC path expander for better performance
// This requires APOC to be installed in Neo4j
// Original query:
// MATCH path = (start:Host {ip: $start_ip})
// -[:RUNS|HAS_VULNERABILITY|CONNECTS_TO*]->
// (end:Host {ip: $target_ip})
// RETURN path

// Optimized query with APOC path expander:
CALL apoc.path.expandConfig(
    // Start node
    {ip: $start_ip}, 
    {
        // Relationship types to follow
        relationshipFilter: "RUNS>|HAS_VULNERABILITY>|CONNECTS_TO>",
        // Max depth
        maxLevel: 10,
        // Terminate paths at target node
        terminatorNodes: [{ip: $target_ip}],
        // Only include paths that reach the target
        uniqueness: "NODE_PATH"
    }
) YIELD path
// Filter paths to ensure they contain relevant vulnerabilities
WHERE ALL(r IN relationships(path) WHERE 
    (type(r) = 'RUNS' AND (
        exists((startNode(r))-[:HAS_VULNERABILITY]->()) OR 
        exists((endNode(r))-[:HAS_VULNERABILITY]->()) OR
        exists((endNode(r))-[:IS_VULNERABLE_TO]->())
    )) OR
    type(r) = 'HAS_VULNERABILITY' OR
    (type(r) = 'CONNECTS_TO' AND (
        exists((startNode(r))-[:HAS_VULNERABILITY]->()) OR
        exists((endNode(r))-[:HAS_VULNERABILITY]->())
    ))
)
// Calculate risk score for each path
WITH path, reduce(risk = 0, r IN relationships(path) | risk + coalesce(r.risk, 0.0)) AS pathRisk
// Return paths ordered by risk score
RETURN path, pathRisk
ORDER BY pathRisk DESC
LIMIT 10;

// Fallback query if APOC is not available:
MATCH path = (start:Host {ip: $start_ip})
-[:RUNS|HAS_VULNERABILITY|CONNECTS_TO*1..10]->
(end:Host {ip: $target_ip})
WHERE ALL(r IN relationships(path) WHERE 
    (type(r) = 'RUNS' AND (
        exists((startNode(r))-[:HAS_VULNERABILITY]->()) OR 
        exists((endNode(r))-[:HAS_VULNERABILITY]->()) OR
        exists((endNode(r))-[:IS_VULNERABLE_TO]->())
    )) OR
    type(r) = 'HAS_VULNERABILITY' OR
    (type(r) = 'CONNECTS_TO' AND (
        exists((startNode(r))-[:HAS_VULNERABILITY]->()) OR
        exists((endNode(r))-[:HAS_VULNERABILITY]->())
    ))
)
WITH path, reduce(risk = 0, r IN relationships(path) | risk + coalesce(r.risk, 0.0)) AS pathRisk
RETURN path, pathRisk
ORDER BY pathRisk DESC
LIMIT 10;

// Optimize vulnerability impact query with better filtering, pagination and caching hints
// Original query:
// MATCH (h:Host)-[:HAS_VULNERABILITY]->(v:Vulnerability)
// RETURN h.ip, collect(v) as vulnerabilities

// Optimized query with filtering, sorting, and pagination:
// Parameters: $severity (optional filter), $skip (pagination offset), $limit (page size)
MATCH (h:Host)
WHERE 
    // Only include hosts with vulnerabilities
    EXISTS {
        MATCH (h)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        // Optional severity filter
        WHERE $severity IS NULL OR v.severity = $severity
    }
WITH h
// Get vulnerabilities for each host
MATCH (h)-[:HAS_VULNERABILITY]->(v:Vulnerability)
// Optional severity filter
WHERE $severity IS NULL OR v.severity = $severity
// Order vulnerabilities by CVSS score (most critical first)
WITH h, v
ORDER BY v.cvss DESC
// Group vulnerabilities by host
WITH h, collect({
    id: v.id, 
    name: v.name, 
    severity: v.severity, 
    cvss: v.cvss,
    description: v.description,
    published_date: v.published_date,
    remediation: v.remediation
}) as vulnerabilities
// Calculate total vulnerability count and highest CVSS for each host
WITH 
    h.ip as ip, 
    h.hostname as hostname, 
    h.os as os,
    h.last_seen as last_seen,
    vulnerabilities,
    size(vulnerabilities) as vuln_count,
    CASE WHEN size(vulnerabilities) > 0 THEN vulnerabilities[0].cvss ELSE 0 END as highest_cvss
// Order hosts by vulnerability count and highest CVSS
ORDER BY vuln_count DESC, highest_cvss DESC
// Support pagination
SKIP $skip
LIMIT $limit
RETURN ip, hostname, os, last_seen, vulnerabilities, vuln_count, highest_cvss;

// Query to get vulnerability statistics by severity
MATCH (v:Vulnerability)<-[:HAS_VULNERABILITY]-(h:Host)
WITH v.severity AS severity, count(DISTINCT v) AS unique_vulns, count(h) AS affected_hosts
RETURN severity, unique_vulns, affected_hosts
ORDER BY 
    CASE severity
        WHEN 'Critical' THEN 1
        WHEN 'High' THEN 2
        WHEN 'Medium' THEN 3
        WHEN 'Low' THEN 4
        ELSE 5
    END;

// Query to find hosts with the most critical vulnerabilities
MATCH (h:Host)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WHERE v.severity IN ['Critical', 'High']
WITH h, count(v) AS critical_vulns
ORDER BY critical_vulns DESC
LIMIT 10
MATCH (h)-[:HAS_VULNERABILITY]->(v:Vulnerability)
RETURN h.ip, h.hostname, collect({id: v.id, name: v.name, severity: v.severity, cvss: v.cvss}) AS vulnerabilities, critical_vulns;

//=============================================================================
// MAINTENANCE PROCEDURES
//=============================================================================

// Procedure to clean up old scan data (keep only the last N scans)
// This should be run periodically to prevent database bloat
// Parameters: $keep_scans (number of recent scans to keep)
MATCH (s:Scan)
WITH s
ORDER BY s.time DESC
SKIP $keep_scans
WITH collect(s) AS old_scans
UNWIND old_scans AS old_scan
OPTIONAL MATCH (old_scan)<-[r]-()
DELETE r
WITH old_scan
DETACH DELETE old_scan;

//=============================================================================
// CONFIGURATION NOTES
//=============================================================================

// Note: Memory optimization settings should be in neo4j.conf, not in Cypher scripts
// For reference, recommended settings for a system with 8GB RAM are:
// dbms.memory.heap.initial_size=1G
// dbms.memory.heap.max_size=4G
// dbms.memory.pagecache.size=2G
// dbms.jvm.additional=-XX:+UseG1GC
// dbms.jvm.additional=-XX:+DisableExplicitGC
// dbms.jvm.additional=-XX:+ExitOnOutOfMemoryError

// For larger systems (16GB+ RAM), consider:
// dbms.memory.heap.initial_size=4G
// dbms.memory.heap.max_size=8G
// dbms.memory.pagecache.size=6G
