"""
Service Enumerator module for the SKrulll Orchestrator.

This module provides functionality for enumerating services, protocols, and
identifying software versions and potential vulnerabilities.
"""
import logging
import socket
import time
import re
from typing import Dict, List, Any, Optional, Tuple, Union
import yaml
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    logging.warning("python-nmap not installed, service detection will be limited")
    NMAP_AVAILABLE = False

try:
    import paramiko
    SSH_AVAILABLE = True
except ImportError:
    logging.warning("paramiko not installed, SSH enumeration will be limited")
    SSH_AVAILABLE = False

try:
    import cvss
    CVSS_AVAILABLE = True
except ImportError:
    logging.warning("cvss not installed, vulnerability scoring will be limited")
    CVSS_AVAILABLE = False

logger = logging.getLogger(__name__)

# Common service ports to check
COMMON_PORTS = {
    'HTTP': [80, 8080, 8000, 8008, 8088],
    'HTTPS': [443, 8443, 4443],
    'FTP': [21],
    'SSH': [22, 2222],
    'TELNET': [23],
    'SMTP': [25, 587, 465],
    'DNS': [53],
    'POP3': [110, 995],
    'IMAP': [143, 993],
    'SMB': [139, 445],
    'RDP': [3389],
    'MSSQL': [1433],
    'MYSQL': [3306],
    'POSTGRES': [5432],
    'REDIS': [6379],
    'MONGODB': [27017, 27018, 27019],
    'ELASTICSEARCH': [9200, 9300]
}

# Regular expressions for service banners
SERVICE_PATTERNS = {
    'HTTP': re.compile(r'(?i)HTTP/(1\.0|1\.1|2)'),
    'SSH': re.compile(r'(?i)SSH-([.\d]+)'),
    'FTP': re.compile(r'(?i)FTP|FileZilla|ProFTPD|vsftpd|FileZilla'),
    'SMTP': re.compile(r'(?i)SMTP|Postfix|Sendmail|Exim|Microsoft Exchange'),
    'POP3': re.compile(r'(?i)POP3'),
    'IMAP': re.compile(r'(?i)IMAP'),
    'SMB': re.compile(r'(?i)SMB|Samba|Windows'),
    'TELNET': re.compile(r'(?i)TELNET'),
    'MSSQL': re.compile(r'(?i)Microsoft SQL Server'),
    'MYSQL': re.compile(r'(?i)MySQL'),
    'POSTGRES': re.compile(r'(?i)PostgreSQL'),
    'REDIS': re.compile(r'(?i)Redis'),
    'MONGODB': re.compile(r'(?i)MongoDB'),
    'ELASTICSEARCH': re.compile(r'(?i)Elasticsearch')
}

# Version extraction patterns
VERSION_PATTERNS = {
    'HTTP': re.compile(r'(?i)Server: ([^\r\n]+)'),
    'SSH': re.compile(r'(?i)SSH-2.0-([^\r\n]+)'),
    'FTP': re.compile(r'(?i)220[- ]([^\r\n]+)'),
    'SMTP': re.compile(r'(?i)220[- ]([^\r\n]+)'),
    'POP3': re.compile(r'(?i)\+OK ([^\r\n]+)'),
    'IMAP': re.compile(r'(?i)\* OK ([^\r\n]+)'),
    'TELNET': re.compile(r'([^\r\n]+)'),
    'MYSQL': re.compile(r'([0-9]+\.[0-9]+\.[0-9]+)'),
    'POSTGRES': re.compile(r'PostgreSQL ([0-9]+\.[0-9]+)'),
    'REDIS': re.compile(r'redis_version:([0-9]+\.[0-9]+\.[0-9]+)')
}

# Security probe payloads for each protocol
PROBE_PAYLOADS = {
    'HTTP': b'GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: SKrulll/1.0\r\n\r\n',
    'HTTPS': b'GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: SKrulll/1.0\r\n\r\n',
    'FTP': b'',  # Empty payload, FTP server sends banner upon connection
    'SSH': b'',  # Empty payload, SSH server sends banner upon connection
    'SMTP': b'EHLO cyberops.local\r\n',
    'POP3': b'',  # Empty payload, POP3 server sends banner upon connection
    'IMAP': b'A001 CAPABILITY\r\n',
    'TELNET': b'',  # Empty payload, Telnet server sends banner upon connection
    'SMB': b'\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00'
}

# Risk scoring weights (adjust based on your security priorities)
RISK_WEIGHTS = {
    'version_disclosure': 0.2,
    'outdated_version': 0.5,
    'plaintext_auth': 0.7,
    'weak_encryption': 0.6,
    'known_vulnerability': 0.9,
    'public_access': 0.4,
    'sensitive_service': 0.5
}

# CVSS Base Score for known vulnerable services
VULNERABLE_SERVICES = {
    'OpenSSH 7.2p1': {'cvss_vector': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'cve': 'CVE-2016-6515'},
    'Apache 2.4.49': {'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'cve': 'CVE-2021-41773'},
    'ProFTPD 1.3.5': {'cvss_vector': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'cve': 'CVE-2015-3306'},
    'Exim 4.87': {'cvss_vector': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'cve': 'CVE-2017-16943'},
    'Microsoft Exchange Server 2019 CU1': {'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'cve': 'CVE-2021-26855'},
    'Windows SMBv1': {'cvss_vector': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'cve': 'CVE-2017-0144'},
    'MySQL 5.5.60': {'cvss_vector': 'CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', 'cve': 'CVE-2018-2784'},
    'Redis 4.0.0': {'cvss_vector': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'cve': 'CVE-2018-0618'},
    'MongoDB 3.4.0': {'cvss_vector': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 'cve': 'CVE-2018-1000002'},
    'Elasticsearch 6.4.0': {'cvss_vector': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 'cve': 'CVE-2018-17246'}
}


@dataclass
class ServiceInfo:
    """Information about a detected service."""
    host: str
    port: int
    protocol: str = "unknown"
    service: str = "unknown"
    version: str = "unknown"
    banner: str = ""
    status: str = "closed"
    risk_score: float = 0.0
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    additional_info: Dict[str, Any] = field(default_factory=dict)


class ServiceEnumerator:
    """
    Enumerates services on target systems and performs protocol-specific probes.
    """

    def __init__(self, timeout: int = 2, max_threads: int = 50):
        """
        Initialize the service enumerator.
        
        Args:
            timeout: Timeout in seconds for connection attempts
            max_threads: Maximum number of concurrent threads for scanning
        """
        self.timeout = timeout
        self.max_threads = max_threads
        self.nmap_scanner = None
        
        # Initialize nmap scanner if available
        if NMAP_AVAILABLE:
            try:
                self.nmap_scanner = nmap.PortScanner()
                logger.info("Initialized nmap scanner")
            except Exception as e:
                logger.error(f"Failed to initialize nmap scanner: {str(e)}")
        
        logger.info(f"Initialized service enumerator with timeout={timeout}s, max_threads={max_threads}")
    
    def enumerate_host(self, 
                      target: str, 
                      ports: Optional[List[int]] = None, 
                      protocols: Optional[List[str]] = None,
                      use_nmap: bool = True) -> Dict[str, Any]:
        """
        Enumerate services on a target host.
        
        Args:
            target: Target hostname or IP address
            ports: List of ports to check (if None, check common ports)
            protocols: List of protocols to check (if None, check all protocols)
            use_nmap: Whether to use nmap for scanning (if available)
            
        Returns:
            Dictionary containing enumeration results
        """
        if not ports:
            ports = []
            for protocol_ports in COMMON_PORTS.values():
                ports.extend(protocol_ports)
            ports = sorted(list(set(ports)))
        
        if not protocols:
            protocols = list(COMMON_PORTS.keys())
        
        logger.info(f"Starting service enumeration on {target} (ports: {len(ports)}, protocols: {len(protocols)})")
        
        results = {
            "target": target,
            "timestamp": time.time(),
            "total_ports": len(ports),
            "open_ports": 0,
            "services": [],
            "vulnerabilities": [],
            "risk_assessment": {
                "overall_score": 0.0,
                "risk_factors": []
            }
        }
        
        # First, perform a basic port scan to identify open ports
        open_ports = self._scan_ports(target, ports)
        results["open_ports"] = len(open_ports)
        
        # Use nmap for service detection if available and requested
        if use_nmap and NMAP_AVAILABLE and self.nmap_scanner and open_ports:
            service_results = self._nmap_service_detection(target, open_ports)
        else:
            # Fallback to our own service probes
            service_results = self._probe_services(target, open_ports, protocols)
        
        # Add service results
        results["services"] = [asdict(service) for service in service_results]
        
        # Perform vulnerability assessment and risk scoring
        vulnerabilities, risk_assessment = self._assess_vulnerabilities(service_results)
        results["vulnerabilities"] = vulnerabilities
        results["risk_assessment"] = risk_assessment
        
        return results
    
    def _scan_ports(self, target: str, ports: List[int]) -> List[int]:
        """
        Perform a basic port scan to identify open ports.
        
        Args:
            target: Target hostname or IP address
            ports: List of ports to scan
            
        Returns:
            List of open ports
        """
        open_ports = []
        
        # Use ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Map port scanning to threads
            port_results = list(executor.map(
                lambda port: (port, self._check_port(target, port)), 
                ports
            ))
            
            # Collect open ports
            for port, is_open in port_results:
                if is_open:
                    open_ports.append(port)
                    logger.debug(f"Port {port} is open on {target}")
        
        logger.info(f"Completed port scan on {target}, found {len(open_ports)} open ports")
        return open_ports
    
    def _check_port(self, target: str, port: int) -> bool:
        """
        Check if a port is open.
        
        Args:
            target: Target hostname or IP address
            port: Port to check
            
        Returns:
            True if port is open, False otherwise
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((target, port))
                return result == 0
        except (socket.gaierror, socket.error) as e:
            logger.debug(f"Error checking port {port} on {target}: {str(e)}")
            return False
    
    def _nmap_service_detection(self, target: str, ports: List[int]) -> List[ServiceInfo]:
        """
        Use nmap for service detection.
        
        Args:
            target: Target hostname or IP address
            ports: List of open ports to scan
            
        Returns:
            List of ServiceInfo objects with detected services
        """
        logger.info(f"Using nmap for service detection on {target}")
        services = []
        
        try:
            # Prepare port list for nmap
            port_list = ",".join(map(str, ports))
            
            # Run nmap scan with service detection
            self.nmap_scanner.scan(target, port_list, arguments="-sV -sS -Pn")
            
            # Process results
            if target in self.nmap_scanner.all_hosts():
                for port in ports:
                    if str(port) in self.nmap_scanner[target].get('tcp', {}):
                        port_info = self.nmap_scanner[target]['tcp'][str(port)]
                        service = ServiceInfo(
                            host=target,
                            port=port,
                            protocol="tcp",
                            service=port_info.get('name', 'unknown'),
                            version=port_info.get('product', '') + ' ' + port_info.get('version', ''),
                            banner=port_info.get('extrainfo', ''),
                            status=port_info.get('state', 'closed')
                        )
                        services.append(service)
            
            logger.info(f"Completed nmap service detection, found {len(services)} services")
            return services
        except Exception as e:
            logger.error(f"Error during nmap service detection: {str(e)}")
            # Fallback to manual probing
            return self._probe_services(target, ports, list(COMMON_PORTS.keys()))
    
    def _probe_services(self, target: str, ports: List[int], protocols: List[str]) -> List[ServiceInfo]:
        """
        Probe services on open ports.
        
        Args:
            target: Target hostname or IP address
            ports: List of open ports to scan
            protocols: List of protocols to check
            
        Returns:
            List of ServiceInfo objects with detected services
        """
        logger.info(f"Probing services on {target} ({len(ports)} ports)")
        services = []
        
        # Use ThreadPoolExecutor for concurrent probing
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Map service probing to threads
            service_results = list(executor.map(
                lambda port: self._probe_service(target, port, protocols), 
                ports
            ))
            
            # Add to services list
            services.extend([s for s in service_results if s is not None])
        
        logger.info(f"Completed service probing, found {len(services)} services")
        return services
    
    def _probe_service(self, target: str, port: int, protocols: List[str]) -> Optional[ServiceInfo]:
        """
        Probe a service on a specific port.
        
        Args:
            target: Target hostname or IP address
            port: Port to probe
            protocols: List of protocols to check
            
        Returns:
            ServiceInfo object if service is detected, None otherwise
        """
        # Initialize service info
        service = ServiceInfo(
            host=target,
            port=port,
            status="open"
        )
        
        # Determine which protocols to try based on port
        protocols_to_try = []
        for protocol, protocol_ports in COMMON_PORTS.items():
            if protocol in protocols and port in protocol_ports:
                protocols_to_try.append(protocol)
        
        # If no specific protocols match this port, try all protocols
        if not protocols_to_try:
            protocols_to_try = protocols
        
        # Try each protocol
        for protocol in protocols_to_try:
            try:
                # Connect to the port
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    sock.connect((target, port))
                    
                    # Send probe payload if available
                    payload = PROBE_PAYLOADS.get(protocol, b'')
                    if payload:
                        sock.send(payload)
                    
                    # Receive response
                    response = sock.recv(4096)
                    
                    # Convert to string for analysis (handle binary data gracefully)
                    banner = ""
                    try:
                        banner = response.decode('utf-8', errors='ignore')
                    except Exception:
                        banner = str(response)
                    
                    # Check if response matches this protocol
                    if protocol == 'HTTP' and response.startswith(b'HTTP/'):
                        service.protocol = "tcp"
                        service.service = "http"
                        service.banner = banner
                        
                        # Extract version information
                        server_match = VERSION_PATTERNS['HTTP'].search(banner)
                        if server_match:
                            service.version = server_match.group(1)
                        
                        # Additional information for HTTP
                        service.additional_info["http_headers"] = self._parse_http_headers(banner)
                        break
                    
                    elif protocol == 'SSH' and response.startswith(b'SSH-'):
                        service.protocol = "tcp"
                        service.service = "ssh"
                        service.banner = banner
                        
                        # Extract version information
                        version_match = VERSION_PATTERNS['SSH'].search(banner)
                        if version_match:
                            service.version = version_match.group(1)
                        break
                    
                    # Check other protocols based on pattern matching
                    else:
                        for proto, pattern in SERVICE_PATTERNS.items():
                            if pattern.search(banner):
                                service.protocol = "tcp"
                                service.service = proto.lower()
                                service.banner = banner
                                
                                # Extract version information if available
                                if proto in VERSION_PATTERNS:
                                    version_match = VERSION_PATTERNS[proto].search(banner)
                                    if version_match:
                                        service.version = version_match.group(1)
                                break
                        
                        if service.service != "unknown":
                            break
            
            except (socket.timeout, ConnectionRefusedError):
                # This protocol didn't work, try the next one
                continue
            except Exception as e:
                logger.debug(f"Error probing {protocol} on {target}:{port}: {str(e)}")
                continue
        
        # If we identified a service, return the result
        if service.service != "unknown":
            return service
        
        # Otherwise, create a generic service entry
        service.service = f"unknown-{port}"
        return service
    
    def _parse_http_headers(self, response: str) -> Dict[str, str]:
        """
        Parse HTTP headers from response.
        
        Args:
            response: HTTP response as string
            
        Returns:
            Dictionary of HTTP headers
        """
        headers = {}
        lines = response.split('\r\n')
        
        # Skip the status line
        for line in lines[1:]:
            if not line or line.isspace():
                break
                
            if ': ' in line:
                key, value = line.split(': ', 1)
                headers[key] = value
        
        return headers
    
    def _assess_vulnerabilities(self, services: List[ServiceInfo]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Assess vulnerabilities and calculate risk score.
        
        Args:
            services: List of ServiceInfo objects
            
        Returns:
            Tuple of (vulnerabilities list, risk assessment dict)
        """
        vulnerabilities = []
        risk_factors = []
        total_risk_score = 0.0
        max_risk = 0.0
        
        for service in services:
            service_vulns = []
            service_risk = 0.0
            
            # Check for version disclosure
            if service.version != "unknown":
                risk = RISK_WEIGHTS['version_disclosure']
                service_risk += risk
                max_risk += RISK_WEIGHTS['version_disclosure']
                risk_factors.append({
                    "factor": "version_disclosure",
                    "service": f"{service.service} on port {service.port}",
                    "risk_value": risk
                })
                
                # Check for known vulnerable version
                for vuln_service, vuln_info in VULNERABLE_SERVICES.items():
                    if vuln_service in service.version:
                        risk = RISK_WEIGHTS['known_vulnerability']
                        service_risk += risk
                        max_risk += RISK_WEIGHTS['known_vulnerability']
                        
                        # Create vulnerability entry
                        vulnerability = {
                            "service": service.service,
                            "port": service.port,
                            "version": service.version,
                            "cve": vuln_info['cve'],
                            "severity": "high",
                            "description": f"Known vulnerable version of {service.service}",
                            "recommendation": f"Upgrade {service.service} to the latest version"
                        }
                        
                        # Add CVSS scoring if available
                        if CVSS_AVAILABLE:
                            try:
                                cvss_vector = vuln_info['cvss_vector']
                                cvss_obj = cvss.CVSS3(cvss_vector)
                                vulnerability["cvss_vector"] = cvss_vector
                                vulnerability["cvss_base_score"] = cvss_obj.base_score
                                vulnerability["cvss_severity"] = cvss_obj.severity
                            except Exception as e:
                                logger.debug(f"Error parsing CVSS vector: {str(e)}")
                        
                        vulnerabilities.append(vulnerability)
                        service_vulns.append(vulnerability)
                        
                        risk_factors.append({
                            "factor": "known_vulnerability",
                            "service": f"{service.service} on port {service.port}",
                            "details": f"Vulnerable to {vuln_info['cve']}",
                            "risk_value": risk
                        })
            
            # Check for plaintext protocols
            plaintext_protocols = ["ftp", "telnet", "http", "pop3", "imap", "smtp"]
            if service.service.lower() in plaintext_protocols:
                risk = RISK_WEIGHTS['plaintext_auth']
                service_risk += risk
                max_risk += RISK_WEIGHTS['plaintext_auth']
                
                # Create vulnerability entry
                vulnerability = {
                    "service": service.service,
                    "port": service.port,
                    "severity": "medium",
                    "description": f"{service.service.upper()} service transmits data in plaintext",
                    "recommendation": f"Replace {service.service.upper()} with an encrypted alternative"
                }
                
                vulnerabilities.append(vulnerability)
                service_vulns.append(vulnerability)
                
                risk_factors.append({
                    "factor": "plaintext_protocol",
                    "service": f"{service.service} on port {service.port}",
                    "risk_value": risk
                })
            
            # Check for sensitive services exposed to public
            sensitive_services = ["mysql", "postgres", "mongodb", "redis", "elasticsearch"]
            if service.service.lower() in sensitive_services:
                risk = RISK_WEIGHTS['sensitive_service']
                service_risk += risk
                max_risk += RISK_WEIGHTS['sensitive_service']
                
                # Create vulnerability entry
                vulnerability = {
                    "service": service.service,
                    "port": service.port,
                    "severity": "high",
                    "description": f"Sensitive {service.service.upper()} service exposed",
                    "recommendation": f"Restrict {service.service.upper()} access with firewall rules"
                }
                
                vulnerabilities.append(vulnerability)
                service_vulns.append(vulnerability)
                
                risk_factors.append({
                    "factor": "sensitive_service_exposed",
                    "service": f"{service.service} on port {service.port}",
                    "risk_value": risk
                })
            
            # Update service risk score
            service.risk_score = service_risk
            service.vulnerabilities = service_vulns
            
            # Add to total risk
            total_risk_score += service_risk
        
        # Calculate normalized overall risk score (0-10 scale)
        overall_score = 0
        if max_risk > 0:
            overall_score = (total_risk_score / max_risk) * 10
        
        # Determine overall severity
        severity = "low"
        if overall_score >= 7:
            severity = "high"
        elif overall_score >= 4:
            severity = "medium"
        
        # Create risk assessment
        risk_assessment = {
            "overall_score": round(overall_score, 2),
            "severity": severity,
            "risk_factors": risk_factors,
            "total_vulnerabilities": len(vulnerabilities)
        }
        
        return vulnerabilities, risk_assessment
    
    def generate_report(self, results: Dict[str, Any], format: str = 'yaml') -> str:
        """
        Generate a formatted report of enumeration results.
        
        Args:
            results: Enumeration results dictionary
            format: Output format ('yaml', 'json')
            
        Returns:
            Formatted report as string
        """
        if format == 'yaml':
            return yaml.dump(results, sort_keys=False)
        else:  # json
            return json.dumps(results, indent=2)
    
    def test_service_ssh(self, target: str, port: int = 22) -> Dict[str, Any]:
        """
        Perform extended tests on SSH service.
        
        Args:
            target: Target hostname or IP address
            port: SSH port
            
        Returns:
            Dictionary with test results
        """
        if not SSH_AVAILABLE:
            return {"error": "SSH module (paramiko) not available"}
        
        results = {
            "host": target,
            "port": port,
            "service": "ssh",
            "supported_auth_methods": [],
            "key_exchange_algorithms": [],
            "encryption_algorithms": [],
            "mac_algorithms": [],
            "compression_algorithms": [],
            "issues": []
        }
        
        try:
            # Transport level connection to get capability information
            transport = paramiko.Transport((target, port))
            transport.start_client()
            
            # Get supported algorithms
            kex_algs = transport.get_security_options().kex
            cipher_algs = transport.get_security_options().ciphers
            mac_algs = transport.get_security_options().digests
            comp_algs = transport.get_security_options().compression
            
            results["key_exchange_algorithms"] = kex_algs
            results["encryption_algorithms"] = cipher_algs
            results["mac_algorithms"] = mac_algs
            results["compression_algorithms"] = comp_algs
            
            # Check for weak algorithms
            weak_kex = set(kex_algs) & {"diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1"}
            weak_ciphers = set(cipher_algs) & {"3des-cbc", "blowfish-cbc", "arcfour"}
            weak_macs = set(mac_algs) & {"hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96"}
            
            if weak_kex:
                results["issues"].append({
                    "type": "weak_key_exchange",
                    "severity": "high",
                    "description": f"Weak key exchange algorithms supported: {', '.join(weak_kex)}",
                    "recommendation": "Disable weak key exchange algorithms in SSH configuration"
                })
            
            if weak_ciphers:
                results["issues"].append({
                    "type": "weak_ciphers",
                    "severity": "high",
                    "description": f"Weak encryption algorithms supported: {', '.join(weak_ciphers)}",
                    "recommendation": "Disable weak encryption algorithms in SSH configuration"
                })
            
            if weak_macs:
                results["issues"].append({
                    "type": "weak_macs",
                    "severity": "medium",
                    "description": f"Weak MAC algorithms supported: {', '.join(weak_macs)}",
                    "recommendation": "Disable weak MAC algorithms in SSH configuration"
                })
            
            # Clean up
            transport.close()
            
            # Try to get supported authentication methods
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            try:
                # This will likely fail due to authentication, but we'll catch the error to get auth methods
                ssh.connect(target, port=port, username="invalid_user", password="invalid_password", timeout=self.timeout)
            except paramiko.ssh_exception.AuthenticationException as e:
                # Check if we can extract auth methods from the exception
                auth_methods = []
                if hasattr(e, 'allowed_types') and e.allowed_types:
                    auth_methods = e.allowed_types
                
                results["supported_auth_methods"] = auth_methods
                
                # Check for password authentication
                if "password" in auth_methods:
                    results["issues"].append({
                        "type": "password_auth_enabled",
                        "severity": "medium",
                        "description": "Password authentication is enabled",
                        "recommendation": "Consider using only key-based authentication for SSH"
                    })
            except Exception:
                pass
            
            # Clean up
            ssh.close()
            
            return results
        except Exception as e:
            logger.debug(f"Error testing SSH service: {str(e)}")
            return {"error": str(e)}
    
    def test_service_http(self, target: str, port: int, is_https: bool = False) -> Dict[str, Any]:
        """
        Perform extended tests on HTTP service.
        
        Args:
            target: Target hostname or IP address
            port: HTTP port
            is_https: Whether the service uses HTTPS
            
        Returns:
            Dictionary with test results
        """
        import ssl
        import http.client
        
        results = {
            "host": target,
            "port": port,
            "service": "https" if is_https else "http",
            "server": "",
            "headers": {},
            "security_headers": {},
            "issues": []
        }
        
        try:
            # Create HTTP connection
            if is_https:
                # Disable certificate verification for testing purposes
                context = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(target, port, timeout=self.timeout, context=context)
            else:
                conn = http.client.HTTPConnection(target, port, timeout=self.timeout)
            
            # Send a request to get headers
            conn.request("HEAD", "/")
            response = conn.getresponse()
            
            # Get response headers
            headers = {k.lower(): v for k, v in response.getheaders()}
            results["headers"] = dict(response.getheaders())
            results["status"] = response.status
            
            # Extract server information
            if "server" in headers:
                results["server"] = headers["server"]
            
            # Check security headers
            security_headers = {
                "strict-transport-security": False,
                "content-security-policy": False,
                "x-frame-options": False,
                "x-xss-protection": False,
                "x-content-type-options": False
            }
            
            for header in security_headers:
                if header in headers:
                    security_headers[header] = True
            
            results["security_headers"] = security_headers
            
            # Check for security issues
            if not is_https:
                results["issues"].append({
                    "type": "cleartext_http",
                    "severity": "high",
                    "description": "HTTP service running without encryption",
                    "recommendation": "Implement HTTPS with a valid SSL/TLS certificate"
                })
            
            for header, present in security_headers.items():
                if not present:
                    results["issues"].append({
                        "type": "missing_security_header",
                        "header": header,
                        "severity": "medium",
                        "description": f"Missing security header: {header}",
                        "recommendation": f"Implement the {header} security header"
                    })
            
            # Check for server information disclosure
            if "server" in headers and len(headers["server"]) > 0:
                results["issues"].append({
                    "type": "server_disclosure",
                    "severity": "low",
                    "description": f"Server header discloses version information: {headers['server']}",
                    "recommendation": "Configure server to hide version information"
                })
            
            # Clean up
            conn.close()
            
            return results
        except Exception as e:
            logger.debug(f"Error testing HTTP service: {str(e)}")
            return {"error": str(e)}
    
    def monitor_service(self, target: str, port: int, service: str, interval: int = 60) -> None:
        """
        Set up monitoring for a service.
        
        Args:
            target: Target hostname or IP address
            port: Service port
            service: Service name
            interval: Monitoring interval in seconds
        """
        # This is a placeholder for service monitoring implementation
        # In a real implementation, this would set up persistent monitoring
        # and trigger alerts when service status changes
        logger.info(f"Set up monitoring for {service} on {target}:{port} with interval {interval}s")
        
        # Example monitoring configuration that would be returned in a real implementation
        monitoring_config = {
            "target": target,
            "port": port,
            "service": service,
            "interval": interval,
            "monitors": [
                {
                    "type": "connectivity",
                    "threshold": "5s",
                    "alert_after": 3
                },
                {
                    "type": "banner_change",
                    "alert": True
                },
                {
                    "type": "version_change",
                    "alert": True
                }
            ],
            "notification_channels": [
                "log",
                "webhook"
            ]
        }
        
        return monitoring_config


# Command-line utility for testing
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Service Enumerator")
    parser.add_argument("target", help="Target hostname or IP")
    parser.add_argument("--ports", nargs="*", type=int, help="Ports to scan")
    parser.add_argument("--timeout", type=int, default=2, help="Connection timeout in seconds")
    parser.add_argument("--no-nmap", action="store_true", help="Don't use nmap even if available")
    parser.add_argument("--output", choices=["yaml", "json"], default="yaml", help="Output format")
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Initialize enumerator
    enumerator = ServiceEnumerator(timeout=args.timeout)
    
    # Run enumeration
    results = enumerator.enumerate_host(
        args.target,
        ports=args.ports,
        use_nmap=not args.no_nmap
    )
    
    # Output results
    print(enumerator.generate_report(results, args.output))