"""
Port Scanner module for the SKrulll Orchestrator.

This module provides functionality for scanning network ports on a target,
detecting open services, and fingerprinting.
"""
import concurrent.futures
import logging
import socket
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)

# Common port descriptions
PORT_DESCRIPTIONS = {
    20: "FTP (Data)",
    21: "FTP (Control)",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP Proxy"
}

# Default ports to scan if none specified
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]


def scan_port(target: str, port: int, timeout: float = 1.0) -> bool:
    """
    Scan a single port on a target.
    
    Args:
        target: Target hostname or IP address
        port: Port number to scan
        timeout: Timeout in seconds
        
    Returns:
        True if port is open, False otherwise
    """
    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Try to connect
        result = sock.connect_ex((target, port))
        
        # Close socket
        sock.close()
        
        # Return True if port is open
        return result == 0
        
    except socket.gaierror:
        logger.error(f"Hostname resolution failed for {target}")
        return False
    except socket.error as e:
        logger.error(f"Socket error on {target}:{port}: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Error scanning {target}:{port}: {str(e)}", exc_info=True)
        return False


def resolve_hostname(target: str) -> Optional[str]:
    """
    Resolve a hostname to an IP address.
    
    Args:
        target: Hostname to resolve
        
    Returns:
        IP address as string, or None if resolution fails
    """
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        logger.error(f"Cannot resolve hostname: {target}")
        return None
    except Exception as e:
        logger.error(f"Error resolving hostname {target}: {str(e)}", exc_info=True)
        return None


def scan_ports(target: str, 
              ports: Optional[List[int]] = None, 
              timeout: float = 1.0,
              max_workers: int = 50) -> Dict[int, bool]:
    """
    Scan multiple ports on a target.
    
    Args:
        target: Target hostname or IP address
        ports: List of ports to scan (if None, use default ports)
        timeout: Timeout in seconds for each port
        max_workers: Maximum number of concurrent workers
        
    Returns:
        Dictionary mapping port numbers to boolean (True if open)
    """
    results = {}
    
    # Use default ports if none specified
    if ports is None or len(ports) == 0:
        ports = DEFAULT_PORTS
    
    # Resolve hostname first
    ip_address = resolve_hostname(target)
    if not ip_address:
        logger.error(f"Cannot scan {target}: hostname resolution failed")
        return {port: False for port in ports}
    
    logger.info(f"Starting port scan of {target} ({ip_address}) on {len(ports)} ports")
    
    start_time = time.time()
    
    # Use ThreadPoolExecutor for concurrent scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit scanning tasks
        future_to_port = {
            executor.submit(scan_port, ip_address, port, timeout): port
            for port in ports
        }
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                is_open = future.result()
                results[port] = is_open
                
                if is_open:
                    service = PORT_DESCRIPTIONS.get(port, "Unknown")
                    logger.info(f"Port {port} is open on {target} ({service})")
            except Exception as e:
                logger.error(f"Error scanning port {port}: {str(e)}", exc_info=True)
                results[port] = False
    
    elapsed_time = time.time() - start_time
    open_ports = [port for port, is_open in results.items() if is_open]
    
    logger.info(f"Port scan completed for {target} in {elapsed_time:.2f} seconds, "
               f"found {len(open_ports)} open ports out of {len(ports)} scanned")
    
    return results


def scan_service_fingerprint(target: str, port: int, timeout: float = 3.0) -> Optional[str]:
    """
    Attempt to fingerprint a service on an open port.
    
    Args:
        target: Target hostname or IP address
        port: Port number to fingerprint
        timeout: Timeout in seconds
        
    Returns:
        Service banner string, or None if not available
    """
    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Connect to the port
        sock.connect((target, port))
        
        # Try to get a banner by sending a generic request
        # This works for some protocols but not all
        if port in [80, 8080, 443]:
            # HTTP request
            sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
        elif port in [21, 22, 25, 110, 143]:
            # These protocols typically send a banner upon connection
            pass
        else:
            # For other protocols, try sending a newline
            sock.send(b"\r\n")
        
        # Receive response (up to 1024 bytes)
        banner = sock.recv(1024)
        
        # Close socket
        sock.close()
        
        # Return decoded banner
        if banner:
            try:
                return banner.decode('utf-8', errors='ignore').strip()
            except UnicodeDecodeError:
                return banner.hex()
        
        return None
        
    except Exception as e:
        logger.debug(f"Could not fingerprint service on {target}:{port}: {str(e)}")
        return None


def scan_host(target: str, 
             ports: Optional[List[int]] = None, 
             timeout: float = 1.0,
             fingerprint: bool = True) -> Dict[str, Any]:
    """
    Perform a comprehensive scan of a host.
    
    Args:
        target: Target hostname or IP address
        ports: List of ports to scan (if None, use default ports)
        timeout: Timeout in seconds for each port
        fingerprint: Whether to attempt service fingerprinting
        
    Returns:
        Dictionary containing scan results
    """
    results = {
        "target": target,
        "ip_address": None,
        "scan_time": time.time(),
        "ports": {},
        "open_ports": []
    }
    
    # Resolve hostname
    ip_address = resolve_hostname(target)
    if not ip_address:
        logger.error(f"Cannot scan {target}: hostname resolution failed")
        return results
    
    results["ip_address"] = ip_address
    
    # Scan ports
    port_results = scan_ports(target, ports, timeout)
    results["ports"] = port_results
    
    # Collect open ports
    open_ports = []
    for port, is_open in port_results.items():
        if is_open:
            port_info = {
                "port": port,
                "service": PORT_DESCRIPTIONS.get(port, "Unknown")
            }
            
            # Attempt fingerprinting if requested
            if fingerprint:
                banner = scan_service_fingerprint(target, port, timeout * 2)
                if banner:
                    port_info["banner"] = banner
            
            open_ports.append(port_info)
    
    results["open_ports"] = open_ports
    
    return results
