// Initial schema for SKrulll Neo4j database
// This migration creates the base nodes, relationships, and constraints needed for the application

// Create constraints to ensure uniqueness
CREATE CONSTRAINT IF NOT EXISTS FOR (h:Host) REQUIRE h.ip_address IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (s:Service) REQUIRE (s.host_ip, s.port) IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (u:User) REQUIRE u.username IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (t:Target) REQUIRE t.id IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (sr:ScanResult) REQUIRE sr.id IS UNIQUE;

// Create indexes for better performance
CREATE INDEX IF NOT EXISTS FOR (h:Host) ON (h.hostname);
CREATE INDEX IF NOT EXISTS FOR (d:Domain) ON (d.registrar);
CREATE INDEX IF NOT EXISTS FOR (s:Service) ON (s.name);
CREATE INDEX IF NOT EXISTS FOR (v:Vulnerability) ON (v.name);
CREATE INDEX IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity);
CREATE INDEX IF NOT EXISTS FOR (t:Target) ON (t.name);
CREATE INDEX IF NOT EXISTS FOR (sr:ScanResult) ON (sr.timestamp);

// Create some example data
// Create a target
MERGE (t:Target {id: "00000000-0000-0000-0000-000000000001", name: "Example Target", url: "https://example.com"})
SET t.description = "Example target for testing",
    t.tags = ["test", "example"],
    t.created_at = datetime();

// Create a domain
MERGE (d:Domain {name: "example.com"})
SET d.registrar = "Example Registrar",
    d.creation_date = date("2010-01-01"),
    d.expiration_date = date("2030-01-01"),
    d.name_servers = ["ns1.example.com", "ns2.example.com"];

// Link target to domain
MERGE (t:Target {id: "00000000-0000-0000-0000-000000000001"})
MERGE (d:Domain {name: "example.com"})
MERGE (t)-[:CONTAINS]->(d);

// Create some hosts
MERGE (h1:Host {ip_address: "93.184.216.34"})
SET h1.hostname = "example.com",
    h1.os = "Unknown",
    h1.last_seen = datetime();

// Link domain to host
MERGE (d:Domain {name: "example.com"})
MERGE (h:Host {ip_address: "93.184.216.34"})
MERGE (d)-[:RESOLVES_TO]->(h);

// Create some services
MERGE (h:Host {ip_address: "93.184.216.34"})
MERGE (s1:Service {host_ip: "93.184.216.34", port: 80})
SET s1.name = "http",
    s1.product = "nginx",
    s1.version = "1.18.0",
    s1.banner = "nginx/1.18.0",
    s1.last_seen = datetime();

MERGE (h:Host {ip_address: "93.184.216.34"})
MERGE (s2:Service {host_ip: "93.184.216.34", port: 443})
SET s2.name = "https",
    s2.product = "nginx",
    s2.version = "1.18.0",
    s2.banner = "nginx/1.18.0",
    s2.last_seen = datetime();

// Link host to services
MERGE (h:Host {ip_address: "93.184.216.34"})
MERGE (s:Service {host_ip: "93.184.216.34", port: 80})
MERGE (h)-[:RUNS]->(s);

MERGE (h:Host {ip_address: "93.184.216.34"})
MERGE (s:Service {host_ip: "93.184.216.34", port: 443})
MERGE (h)-[:RUNS]->(s);

// Create a scan result
MERGE (sr:ScanResult {id: "00000000-0000-0000-0000-000000000002"})
SET sr.target = "example.com",
    sr.scan_type = "vulnerability_scan",
    sr.timestamp = datetime(),
    sr.status = "completed";

// Link scan result to target
MERGE (t:Target {id: "00000000-0000-0000-0000-000000000001"})
MERGE (sr:ScanResult {id: "00000000-0000-0000-0000-000000000002"})
MERGE (t)-[:HAS_SCAN]->(sr);

// Create a vulnerability
MERGE (v:Vulnerability {id: "00000000-0000-0000-0000-000000000003"})
SET v.name = "SSL Certificate Expiring Soon",
    v.severity = "Medium",
    v.description = "The SSL certificate will expire in 30 days.",
    v.recommendation = "Renew the SSL certificate soon.",
    v.created_at = datetime();

// Link vulnerability to service
MERGE (s:Service {host_ip: "93.184.216.34", port: 443})
MERGE (v:Vulnerability {id: "00000000-0000-0000-0000-000000000003"})
MERGE (s)-[:HAS_VULNERABILITY]->(v);

// Link vulnerability to scan result
MERGE (sr:ScanResult {id: "00000000-0000-0000-0000-000000000002"})
MERGE (v:Vulnerability {id: "00000000-0000-0000-0000-000000000003"})
MERGE (sr)-[:FOUND]->(v);

// Create a user
MERGE (u:User {username: "admin"})
SET u.email = "admin@skrulll.local",
    u.role = "admin",
    u.created_at = datetime();

// Link user to scan result
MERGE (u:User {username: "admin"})
MERGE (sr:ScanResult {id: "00000000-0000-0000-0000-000000000002"})
MERGE (u)-[:CREATED]->(sr);

// Create network topology relationships
MERGE (h1:Host {ip_address: "93.184.216.34"})
MERGE (h2:Host {ip_address: "93.184.216.35"})
SET h2.hostname = "api.example.com",
    h2.os = "Unknown",
    h2.last_seen = datetime();

MERGE (h1)-[:CONNECTS_TO {protocol: "tcp", ports: [80, 443]}]->(h2);

// Create subdomain relationships
MERGE (d1:Domain {name: "example.com"})
MERGE (d2:Domain {name: "api.example.com"})
SET d2.registrar = "Example Registrar",
    d2.creation_date = date("2015-01-01"),
    d2.expiration_date = date("2030-01-01");

MERGE (d2)-[:SUBDOMAIN_OF]->(d1);

// Link domain to host
MERGE (d:Domain {name: "api.example.com"})
MERGE (h:Host {ip_address: "93.184.216.35"})
MERGE (d)-[:RESOLVES_TO]->(h);
