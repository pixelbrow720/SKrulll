"""
Python Bindings for the Rust Network Mapper

This module provides a Python interface to the high-speed Rust network mapper,
integrating with the CyberOps Orchestrator and allowing scanning of network
ranges and discovery of active hosts.
"""
import json
import logging
import os
import subprocess
import tempfile
from typing import Dict, List, Any, Optional, Union

import nmap

logger = logging.getLogger(__name__)

# Define custom error classes for better error handling
class NetworkMapperError(Exception):
    """Base exception for network mapper errors."""
    pass

class ParsingError(NetworkMapperError):
    """Error parsing IP or network."""
    pass

class NetworkError(NetworkMapperError):
    """Network I/O error."""
    pass

class PacketError(NetworkMapperError):
    """Packet crafting error."""
    pass

class TimeoutError(NetworkMapperError):
    """Timeout while scanning."""
    pass

class ConfigError(NetworkMapperError):
    """Invalid configuration."""
    pass

class ScanError(NetworkMapperError):
    """General scanning error."""
    pass

# Error type mapping from Rust error strings to Python exceptions
ERROR_MAPPING = {
    "ParsingError": ParsingError,
    "NetworkError": NetworkError,
    "PacketError": PacketError,
    "TimeoutError": TimeoutError,
    "ConfigError": ConfigError,
    "ScanError": ScanError
}

# Try to import the Rust library if available
try:
    from network_mapper import scan_network as _rust_scan_network
    RUST_AVAILABLE = True
    logger.info("Rust network mapper library loaded")
except ImportError:
    RUST_AVAILABLE = False
    logger.warning("Rust network mapper library not available, falling back to Python implementation")


class NetworkMapper:
    """Python interface to the Network Mapper."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the Network Mapper.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.nm = nmap.PortScanner()
        logger.info("Network Mapper initialized")
    
    def scan_network(self, targets: List[str], method: str = "combined", 
                    timeout_ms: int = 1000, resolve_hostnames: bool = True) -> Dict[str, Any]:
        """
        Scan a network range for active hosts.
        
        Args:
            targets: List of target networks or IPs (CIDR notation supported)
            method: Scan method (icmp, tcp, arp, combined)
            timeout_ms: Timeout in milliseconds
            resolve_hostnames: Whether to resolve hostnames
            
        Returns:
            Dictionary containing scan results
        """
        # Check if we can use the Rust implementation
        if RUST_AVAILABLE:
            return self._scan_rust(targets, method, timeout_ms, resolve_hostnames)
        else:
            return self._scan_python(targets, method, timeout_ms, resolve_hostnames)
    
    def _scan_rust(self, targets: List[str], method: str, 
                  timeout_ms: int, resolve_hostnames: bool) -> Dict[str, Any]:
        """
        Scan using the Rust implementation.
        
        Args:
            targets: List of target networks or IPs
            method: Scan method
            timeout_ms: Timeout in milliseconds
            resolve_hostnames: Whether to resolve hostnames
            
        Returns:
            Dictionary containing scan results
            
        Raises:
            ParsingError: If there's an error parsing IP or network
            NetworkError: If there's a network I/O error
            PacketError: If there's an error crafting packets
            TimeoutError: If the scan times out
            ConfigError: If there's an invalid configuration
            ScanError: If there's a general scanning error
        """
        logger.info(f"Starting Rust network scan on {targets}")
        
        try:
            # Call the Rust function
            results = _rust_scan_network(targets, timeout_ms, method)
            
            # Format results
            active_hosts = []
            for host in results:
                active_hosts.append({
                    "ip": host.ip,
                    "hostname": host.hostname,
                    "mac_address": host.mac_address,
                    "response_time_ms": host.response_time_ms,
                    "discovery_method": host.discovery_method
                })
            
            return {
                "targets": targets,
                "active_hosts": active_hosts,
                "total_hosts": len(active_hosts),
                "scan_method": method,
                "timeout_ms": timeout_ms
            }
        except Exception as e:
            # Parse the error message to determine the error type
            error_msg = str(e)
            error_type = None
            
            # Extract error type from the error message
            for rust_error_type in ERROR_MAPPING.keys():
                if rust_error_type in error_msg:
                    error_type = rust_error_type
                    break
            
            # Log detailed error information
            logger.error(f"Error in Rust network scan: {error_msg} (Type: {error_type or 'Unknown'})")
            
            # If we can map to a specific error type, raise that
            if error_type and error_type in ERROR_MAPPING:
                raise ERROR_MAPPING[error_type](error_msg)
            
            # For unknown errors, fall back to Python implementation with a warning
            logger.warning(f"Falling back to Python implementation due to unhandled Rust error: {error_msg}")
            return self._scan_python(targets, method, timeout_ms, resolve_hostnames)
    
    def _scan_python(self, targets: List[str], method: str,
                    timeout_ms: int, resolve_hostnames: bool) -> Dict[str, Any]:
        """
        Scan using the Python implementation with nmap.
        
        Args:
            targets: List of target networks or IPs
            method: Scan method
            timeout_ms: Timeout in milliseconds
            resolve_hostnames: Whether to resolve hostnames
            
        Returns:
            Dictionary containing scan results
        """
        logger.info(f"Starting Python network scan on {targets}")
        
        # Map scan method to nmap arguments
        method_args = {
            "icmp": "-sn -PE",
            "tcp": "-sS -PS80",
            "arp": "-PR",
            "combined": "-sn -PE -PS80 -PR"
        }
        
        # Set the timeout
        timeout = max(1, timeout_ms // 1000)  # nmap takes seconds
        
        # Build the arguments
        args = f"{method_args.get(method, method_args['combined'])} --min-rate 1000 --max-retries 1 --host-timeout {timeout}s"
        
        if not resolve_hostnames:
            args += " -n"
        
        active_hosts = []
        total_hosts = 0
        
        # Scan each target range
        for target in targets:
            try:
                logger.debug(f"Scanning {target} with args: {args}")
                self.nm.scan(hosts=target, arguments=args)
                
                # Process results
                for host in self.nm.all_hosts():
                    if self.nm[host].state() == 'up':
                        host_info = {
                            "ip": host,
                            "hostname": self.nm[host].hostname() if resolve_hostnames else None,
                            "mac_address": None,
                            "response_time_ms": None,
                            "discovery_method": method
                        }
                        
                        # Try to get MAC address
                        if 'mac' in self.nm[host]['addresses']:
                            host_info["mac_address"] = self.nm[host]['addresses']['mac']
                        
                        active_hosts.append(host_info)
                
                total_hosts += len(self.nm.all_hosts())
            except Exception as e:
                logger.error(f"Error scanning {target}: {str(e)}")
        
        return {
            "targets": targets,
            "active_hosts": active_hosts,
            "total_hosts": len(active_hosts),
            "scan_method": method,
            "timeout_ms": timeout_ms
        }
    
    def scan_with_rust_binary(self, targets: List[str], method: str = "combined",
                            timeout_ms: int = 1000, parallelism: int = 256,
                            resolve_hostnames: bool = True) -> Dict[str, Any]:
        """
        Scan using the compiled Rust binary.
        
        Args:
            targets: List of target networks or IPs
            method: Scan method
            timeout_ms: Timeout in milliseconds
            parallelism: Number of parallel scan threads
            resolve_hostnames: Whether to resolve hostnames
            
        Returns:
            Dictionary containing scan results
            
        Raises:
            FileNotFoundError: If the Rust binary cannot be found
            subprocess.SubprocessError: If there's an error running the binary
            json.JSONDecodeError: If the output cannot be parsed as JSON
            NetworkMapperError: For other network mapper specific errors
        """
        # Find the binary path
        binary_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                                 "..", "target", "release", "network_mapper")
        
        if not os.path.exists(binary_path):
            # Try with .exe extension on Windows
            binary_path += ".exe"
            if not os.path.exists(binary_path):
                raise FileNotFoundError(f"Could not find network mapper binary at {binary_path}")
        
        logger.info(f"Using binary at {binary_path}")
        
        # Create a temporary file for output
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            output_path = tmp.name
        
        try:
            # Build command line arguments
            cmd = [
                binary_path,
                *targets,
                "--method", method,
                "--timeout", str(timeout_ms),
                "--parallelism", str(parallelism),
                "--output", output_path
            ]
            
            if not resolve_hostnames:
                cmd.append("--no-resolve")
            
            # Run the command
            logger.debug(f"Running command: {' '.join(cmd)}")
            subprocess.run(cmd, check=True, capture_output=True)
            
            # Read the results
            with open(output_path, 'r') as f:
                results = json.load(f)
            
            # Format the results
            active_hosts = []
            for host in results:
                active_hosts.append({
                    "ip": host["ip"],
                    "hostname": host.get("hostname"),
                    "mac_address": host.get("mac_address"),
                    "response_time_ms": host.get("response_time_ms"),
                    "discovery_method": host.get("discovery_method")
                })
            
            return {
                "targets": targets,
                "active_hosts": active_hosts,
                "total_hosts": len(active_hosts),
                "scan_method": method,
                "timeout_ms": timeout_ms
            }
        except FileNotFoundError as e:
            logger.error(f"Rust binary not found: {str(e)}")
            logger.warning("Falling back to Python implementation")
            return self._scan_python(targets, method, timeout_ms, resolve_hostnames)
        except subprocess.SubprocessError as e:
            logger.error(f"Error executing Rust binary: {str(e)}")
            logger.warning("Falling back to Python implementation")
            return self._scan_python(targets, method, timeout_ms, resolve_hostnames)
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing Rust binary output: {str(e)}")
            logger.warning("Falling back to Python implementation")
            return self._scan_python(targets, method, timeout_ms, resolve_hostnames)
        except Exception as e:
            logger.error(f"Unexpected error running network mapper binary: {str(e)}")
            logger.warning("Falling back to Python implementation")
            return self._scan_python(targets, method, timeout_ms, resolve_hostnames)
        finally:
            # Clean up temporary file
            try:
                os.unlink(output_path)
            except:
                pass
    
    def visualize_network(self, scan_result: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """
        Generate a network visualization using Graphviz.
        
        Args:
            scan_result: Result from scan_network
            output_path: Path to save the generated image
            
        Returns:
            Path to the generated image
        """
        try:
            import graphviz
        except ImportError:
            logger.error("Graphviz Python package not installed")
            return ""
        
        # Create a new graph
        dot = graphviz.Digraph(comment='Network Map', format='png')
        
        # Add network node
        dot.node('network', 'Network\n' + ', '.join(scan_result["targets"]), shape='cloud')
        
        # Add host nodes
        for host in scan_result["active_hosts"]:
            label = host["ip"]
            if host["hostname"]:
                label += f"\n{host['hostname']}"
            
            node_id = host["ip"].replace(".", "_")
            dot.node(node_id, label, shape='box')
            dot.edge('network', node_id)
        
        # Render the graph
        if output_path:
            result_path = dot.render(output_path, cleanup=True)
        else:
            result_path = dot.render('network_map', cleanup=True)
        
        return result_path
    
    def export_to_neo4j(self, scan_result: Dict[str, Any], uri: str, 
                      username: str, password: str) -> bool:
        """
        Export the network map to Neo4j graph database.
        
        Args:
            scan_result: Result from scan_network
            uri: Neo4j URI
            username: Neo4j username
            password: Neo4j password
            
        Returns:
            True if successful, False otherwise
        """
        try:
            from neo4j import GraphDatabase
        except ImportError:
            logger.error("Neo4j Python package not installed")
            return False
        
        logger.info(f"Exporting network map to Neo4j at {uri}")
        
        try:
            # Connect to Neo4j
            with GraphDatabase.driver(uri, auth=(username, password)) as driver:
                with driver.session() as session:
                    # Create constraints (if they don't exist)
                    session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (n:Network) REQUIRE n.cidr IS UNIQUE")
                    session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (n:Host) REQUIRE n.ip IS UNIQUE")
                    
                    # Create network nodes
                    for target in scan_result["targets"]:
                        session.run("""
                            MERGE (n:Network {cidr: $cidr})
                            SET n.scan_time = $scan_time,
                                n.scan_method = $scan_method
                        """, {
                            "cidr": target,
                            "scan_time": scan_result.get("scan_time", ""),
                            "scan_method": scan_result.get("scan_method", "")
                        })
                    
                    # Create host nodes and relationships
                    for host in scan_result["active_hosts"]:
                        session.run("""
                            MERGE (h:Host {ip: $ip})
                            SET h.hostname = $hostname,
                                h.mac_address = $mac,
                                h.last_seen = datetime(),
                                h.discovery_method = $method
                            WITH h
                            MATCH (n:Network {cidr: $network})
                            MERGE (h)-[:BELONGS_TO]->(n)
                        """, {
                            "ip": host["ip"],
                            "hostname": host.get("hostname", ""),
                            "mac": host.get("mac_address", ""),
                            "method": host.get("discovery_method", ""),
                            "network": scan_result["targets"][0]  # Assumes first target
                        })
            
            logger.info("Successfully exported to Neo4j")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting to Neo4j: {str(e)}")
            return False


# Command-line interface
if __name__ == "__main__":
    import argparse
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Parse arguments
    parser = argparse.ArgumentParser(description="Network Mapper")
    parser.add_argument("targets", nargs="+", help="Target networks or IPs (CIDR notation)")
    parser.add_argument("--method", choices=["icmp", "tcp", "arp", "combined"], 
                       default="combined", help="Scan method")
    parser.add_argument("--timeout", type=int, default=1000, 
                       help="Timeout in milliseconds")
    parser.add_argument("--no-resolve", action="store_true", 
                       help="Don't resolve hostnames")
    parser.add_argument("--use-binary", action="store_true", 
                       help="Use the Rust binary instead of Python binding")
    parser.add_argument("--visualize", action="store_true", 
                       help="Generate visualization")
    parser.add_argument("--output", help="Output file for visualization")
    args = parser.parse_args()
    
    # Create mapper and scan
    mapper = NetworkMapper()
    
    if args.use_binary:
        results = mapper.scan_with_rust_binary(
            args.targets, 
            args.method, 
            args.timeout, 
            resolve_hostnames=not args.no_resolve
        )
    else:
        results = mapper.scan_network(
            args.targets, 
            args.method, 
            args.timeout, 
            resolve_hostnames=not args.no_resolve
        )
    
    # Print results
    print(json.dumps(results, indent=2))
    
    # Generate visualization if requested
    if args.visualize:
        try:
            image_path = mapper.visualize_network(results, args.output)
            print(f"Visualization saved to: {image_path}")
        except Exception as e:
            print(f"Error generating visualization: {e}")
