"""
Network Mapper module for the SKrulll Orchestrator.

This module provides a high-level interface for the Network Mapper, which combines
Rust and Python for high-speed network discovery and mapping, with integration
to Neo4j for graph visualization.

This is a wrapper around the lower-level implementation in:
modules/scanner/netmap/python_bindings/network_mapper.py

This high-level interface adds additional features like NetworkX graph visualization
and direct Neo4j integration, while delegating the actual network scanning to the
lower-level implementation.

Features:
- High-performance network scanning using Rust implementation with Python fallback
- Parallel processing for improved scan speed
- Result caching to avoid redundant scans
- NetworkX graph visualization with customizable output
- Direct Neo4j graph database integration
- Comprehensive error handling and logging
- Memory-efficient processing for large networks
- Adaptive scanning based on target size
- Incremental scanning for very large networks
- Resilient error recovery with graceful degradation
"""
import logging
import json
import os
import sys
import time
import tempfile
import concurrent.futures
import ipaddress
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple, Set

logger = logging.getLogger(__name__)

# Import the Network Mapper from the scanner module
try:
    scanner_path = os.path.join(os.path.dirname(__file__), "..", "scanner", "netmap", "python_bindings")
    sys.path.append(scanner_path)
    from network_mapper import NetworkMapper as LowLevelNetworkMapper
    RUST_MAPPER_AVAILABLE = True
    logger.info("Low-level Network Mapper available (Rust implementation)")
except ImportError:
    RUST_MAPPER_AVAILABLE = False
    logger.warning("Low-level Network Mapper not available, using Python fallback implementation")

# Import the NetworkX for graph handling
try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
    logger.info("NetworkX available for graph visualization")
except ImportError:
    NETWORKX_AVAILABLE = False
    logger.warning("NetworkX not available, network graph visualization will be limited")

# Import Neo4j client if available
try:
    from orchestrator.db.neo4j_client import Neo4jClient
    NEO4J_AVAILABLE = True
    logger.info("Neo4j client available for graph database integration")
except ImportError:
    NEO4J_AVAILABLE = False
    logger.warning("Neo4j client not available, graph database integration will be limited")

# Try to import Redis for caching if available
try:
    import redis
    REDIS_AVAILABLE = True
    logger.info("Redis available for result caching")
except ImportError:
    REDIS_AVAILABLE = False
    logger.debug("Redis not available, using in-memory LRU cache instead")


class NetworkMapper:
    """
    High-level Network Mapper for discovering and mapping networks.
    
    This class wraps the lower-level NetworkMapper implementation from
    modules/scanner/netmap/python_bindings/network_mapper.py and adds
    additional features like NetworkX graph visualization and direct
    Neo4j integration.
    
    Attributes:
        config: Configuration dictionary
        mapper: Low-level network mapper (Rust implementation)
        nm: Python-nmap fallback scanner
        cache: Redis client for caching if available
        cache_ttl: Time-to-live for cached results in seconds
        max_workers: Maximum number of parallel workers for scanning
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the Network Mapper.
        
        Args:
            config: Configuration dictionary with optional keys:
                - redis: Redis configuration for caching
                - neo4j: Neo4j configuration for graph database
                - max_workers: Maximum number of parallel workers
                - cache_ttl: Time-to-live for cached results in seconds
        """
        self.config = config or {}
        self.cache = None
        self.cache_ttl = self.config.get('cache_ttl', 3600)  # Default 1 hour
        self.max_workers = self.config.get('max_workers', 10)
        
        # Initialize Redis cache if available
        if REDIS_AVAILABLE and 'redis' in self.config:
            try:
                redis_config = self.config['redis']
                self.cache = redis.Redis(
                    host=redis_config.get('host', 'localhost'),
                    port=redis_config.get('port', 6379),
                    db=redis_config.get('db', 0),
                    password=redis_config.get('password', None),
                    decode_responses=True
                )
                # Test connection
                self.cache.ping()
                logger.info("Redis cache initialized for network mapper")
            except Exception as e:
                logger.warning(f"Failed to initialize Redis cache: {str(e)}")
                self.cache = None
        
        # Initialize the underlying mapper
        if RUST_MAPPER_AVAILABLE:
            try:
                self.mapper = LowLevelNetworkMapper(self.config)
                logger.info("Rust network mapper initialized")
            except Exception as e:
                logger.error(f"Failed to initialize Rust network mapper: {str(e)}")
                RUST_MAPPER_AVAILABLE = False
                self.mapper = None
        
        # Initialize python-nmap as fallback or if Rust mapper is not available
        if not RUST_MAPPER_AVAILABLE:
            try:
                import nmap
                self.nm = nmap.PortScanner()
                logger.info("Python-nmap fallback initialized")
            except ImportError:
                logger.error("Python-nmap not available, network scanning will be limited")
                self.nm = None
        
        logger.info(f"Network Mapper initialized with max_workers={self.max_workers}, cache_ttl={self.cache_ttl}s")
    
    def _get_cache_key(self, targets: List[str], method: str, timeout_ms: int, 
                      resolve_hostnames: bool) -> str:
        """
        Generate a cache key for scan results.
        
        Args:
            targets: Target networks or IPs
            method: Scan method
            timeout_ms: Timeout in milliseconds
            resolve_hostnames: Whether to resolve hostnames
            
        Returns:
            Cache key string
        """
        # Sort targets for consistent cache keys
        sorted_targets = sorted(targets)
        return f"netmap:{','.join(sorted_targets)}:{method}:{timeout_ms}:{resolve_hostnames}"
    
    def _get_cached_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """
        Get cached scan result if available.
        
        Args:
            cache_key: Cache key string
            
        Returns:
            Cached scan result or None if not found
        """
        if not self.cache:
            return None
            
        try:
            cached_data = self.cache.get(cache_key)
            if cached_data:
                logger.info(f"Using cached scan result for {cache_key}")
                return json.loads(cached_data)
        except Exception as e:
            logger.warning(f"Error retrieving from cache: {str(e)}")
        
        return None
    
    def _cache_result(self, cache_key: str, result: Dict[str, Any]) -> None:
        """
        Cache scan result.
        
        Args:
            cache_key: Cache key string
            result: Scan result to cache
        """
        if not self.cache:
            return
            
        try:
            self.cache.setex(
                cache_key,
                self.cache_ttl,
                json.dumps(result)
            )
            logger.debug(f"Cached scan result for {cache_key} (TTL: {self.cache_ttl}s)")
        except Exception as e:
            logger.warning(f"Error caching result: {str(e)}")
    
    def scan_network(self, targets: Union[str, List[str]], 
                    method: str = "combined",
                    timeout_ms: int = 1000, 
                    parallelism: int = 256,
                    resolve_hostnames: bool = True,
                    use_cache: bool = True) -> Dict[str, Any]:
        """
        Scan a network range for active hosts.
        
        Args:
            targets: Target networks or IPs (CIDR notation)
            method: Scan method (icmp, tcp, arp, combined)
            timeout_ms: Timeout in milliseconds
            parallelism: Number of parallel scan threads
            resolve_hostnames: Whether to resolve hostnames
            use_cache: Whether to use cached results if available
            
        Returns:
            Dictionary containing scan results
        """
        # Normalize targets to list
        if isinstance(targets, str):
            targets = [targets]
        
        # Generate cache key
        cache_key = self._get_cache_key(targets, method, timeout_ms, resolve_hostnames)
        
        # Check cache if enabled
        if use_cache:
            cached_result = self._get_cached_result(cache_key)
            if cached_result:
                return cached_result
        
        logger.info(f"Scanning network: {targets} with method: {method}")
        scan_start_time = datetime.now()
        
        try:
            if RUST_MAPPER_AVAILABLE and self.mapper:
                # Use the Rust implementation
                result = self.mapper.scan_network(targets, method, timeout_ms, resolve_hostnames)
            else:
                # Use the Python fallback implementation
                result = self._scan_with_nmap(targets, method, timeout_ms, resolve_hostnames)
            
            # Add scan metadata
            result["scan_time"] = scan_start_time.isoformat()
            result["scan_duration_ms"] = int((datetime.now() - scan_start_time).total_seconds() * 1000)
            
            # Cache the result
            if use_cache:
                self._cache_result(cache_key, result)
            
            logger.info(f"Scan completed in {result['scan_duration_ms']}ms, found {result['total_hosts']} hosts")
            return result
            
        except Exception as e:
            logger.error(f"Error during network scan: {str(e)}", exc_info=True)
            # Return a minimal result with error information
            return {
                "targets": targets,
                "active_hosts": [],
                "total_hosts": 0,
                "scan_method": method,
                "timeout_ms": timeout_ms,
                "error": str(e),
                "scan_time": scan_start_time.isoformat(),
                "scan_duration_ms": int((datetime.now() - scan_start_time).total_seconds() * 1000)
            }
    
    def _scan_single_target(self, target: str, args: str, method: str) -> List[Dict[str, Any]]:
        """
        Scan a single target with nmap.
        
        Args:
            target: Target network or IP
            args: Nmap arguments
            method: Scan method name
            
        Returns:
            List of host information dictionaries
        """
        import nmap
        scanner = nmap.PortScanner()
        hosts = []
        
        try:
            logger.debug(f"Scanning {target} with args: {args}")
            scanner.scan(hosts=target, arguments=args)
            
            # Process results
            for host in scanner.all_hosts():
                if scanner[host].state() == 'up':
                    host_info = {
                        "ip": host,
                        "hostname": scanner[host].hostname(),
                        "mac_address": None,
                        "response_time_ms": None,
                        "discovery_method": method
                    }
                    
                    # Try to get MAC address
                    if 'mac' in scanner[host]['addresses']:
                        host_info["mac_address"] = scanner[host]['addresses']['mac']
                    
                    hosts.append(host_info)
                    
            return hosts
            
        except Exception as e:
            logger.error(f"Error scanning {target}: {str(e)}")
            return []
    
    def _scan_with_nmap(self, targets: List[str], method: str,
                       timeout_ms: int, resolve_hostnames: bool) -> Dict[str, Any]:
        """
        Fallback scan using Python nmap with parallel processing.
        
        Args:
            targets: Target networks or IPs
            method: Scan method
            timeout_ms: Timeout in milliseconds
            resolve_hostnames: Whether to resolve hostnames
            
        Returns:
            Dictionary containing scan results
        """
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
        
        # Determine the number of workers based on target count and max_workers
        num_workers = min(len(targets), self.max_workers)
        
        # Use ThreadPoolExecutor for parallel scanning
        if num_workers > 1 and len(targets) > 1:
            logger.info(f"Scanning {len(targets)} targets in parallel with {num_workers} workers")
            with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
                # Submit scan jobs
                future_to_target = {
                    executor.submit(self._scan_single_target, target, args, method): target
                    for target in targets
                }
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_target):
                    target = future_to_target[future]
                    try:
                        hosts = future.result()
                        active_hosts.extend(hosts)
                        logger.debug(f"Completed scan of {target}, found {len(hosts)} hosts")
                    except Exception as e:
                        logger.error(f"Exception scanning {target}: {str(e)}")
        else:
            # Sequential scanning for single target or when max_workers is 1
            logger.info(f"Scanning {len(targets)} targets sequentially")
            for target in targets:
                hosts = self._scan_single_target(target, args, method)
                active_hosts.extend(hosts)
        
        return {
            "targets": targets,
            "active_hosts": active_hosts,
            "total_hosts": len(active_hosts),
            "scan_method": method,
            "timeout_ms": timeout_ms
        }
    
    def create_network_graph(self, scan_result: Dict[str, Any]) -> Optional[nx.Graph]:
        """
        Create a NetworkX graph from scan results.
        
        Args:
            scan_result: Result from scan_network
            
        Returns:
            NetworkX graph object or None if NetworkX is not available
        """
        if not NETWORKX_AVAILABLE:
            logger.error("NetworkX not available, cannot create graph")
            return None
        
        # Create a new graph
        G = nx.Graph()
        
        # Add network node
        network_node = "network"
        G.add_node(network_node, type="network", 
                  label=f"Network: {', '.join(scan_result['targets'])}")
        
        # Add host nodes
        for host in scan_result["active_hosts"]:
            host_id = host["ip"].replace(".", "_")
            
            # Create node label
            label = host["ip"]
            if host.get("hostname"):
                label += f"\n{host['hostname']}"
            
            # Add node
            G.add_node(host_id, type="host", ip=host["ip"],
                      hostname=host.get("hostname"),
                      mac_address=host.get("mac_address"),
                      label=label)
            
            # Add edge
            G.add_edge(network_node, host_id)
        
        return G
    
    def visualize_network(self, scan_result: Dict[str, Any], 
                         output_path: Optional[str] = None,
                         format: str = "png",
                         interactive: bool = False) -> str:
        """
        Generate a network visualization using NetworkX and Matplotlib.
        
        Args:
            scan_result: Result from scan_network
            output_path: Path to save the generated image
            format: Output format (png, svg, pdf, html)
            interactive: Whether to generate an interactive visualization (html)
            
        Returns:
            Path to the generated image or HTML file
        """
        if not NETWORKX_AVAILABLE:
            logger.error("NetworkX not available, cannot create visualization")
            return ""
        
        # Create graph
        G = self.create_network_graph(scan_result)
        if not G:
            return ""
        
        # If interactive visualization is requested and format is html
        if interactive and format.lower() == "html":
            try:
                # Try to use pyvis for interactive visualization
                from pyvis.network import Network
                
                # Create a pyvis network
                net = Network(height="750px", width="100%", notebook=False, 
                             directed=False, bgcolor="#222222", font_color="white")
                
                # Add nodes
                for node, attrs in G.nodes(data=True):
                    node_type = attrs.get('type', 'unknown')
                    label = attrs.get('label', node)
                    
                    if node_type == 'network':
                        color = '#ff7f0e'
                        size = 30
                        title = f"Network: {', '.join(scan_result['targets'])}"
                    else:
                        color = '#1f77b4'
                        size = 20
                        ip = attrs.get('ip', '')
                        hostname = attrs.get('hostname', '')
                        mac = attrs.get('mac_address', '')
                        title = f"IP: {ip}<br>Hostname: {hostname}<br>MAC: {mac}"
                    
                    net.add_node(node, label=label, title=title, color=color, size=size)
                
                # Add edges
                for source, target in G.edges():
                    net.add_edge(source, target, color="#aaaaaa")
                
                # Set physics options for better layout
                net.set_options("""
                {
                  "physics": {
                    "forceAtlas2Based": {
                      "gravitationalConstant": -50,
                      "centralGravity": 0.01,
                      "springLength": 100,
                      "springConstant": 0.08
                    },
                    "maxVelocity": 50,
                    "solver": "forceAtlas2Based",
                    "timestep": 0.35,
                    "stabilization": {
                      "enabled": true,
                      "iterations": 1000
                    }
                  }
                }
                """)
                
                # Determine output path
                if output_path:
                    if not output_path.lower().endswith('.html'):
                        output_path = f"{output_path}.html"
                    result_path = output_path
                else:
                    # Create a temporary file
                    with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as tmp:
                        result_path = tmp.name
                
                # Save the network visualization
                net.save_graph(result_path)
                logger.info(f"Interactive network visualization saved to {result_path}")
                return result_path
                
            except ImportError:
                logger.warning("pyvis not available, falling back to static visualization")
                interactive = False
        
        # Static visualization with matplotlib
        try:
            import matplotlib.pyplot as plt
            from matplotlib.colors import LinearSegmentedColormap
        except ImportError:
            logger.error("Matplotlib not available, cannot create visualization")
            return ""
        
        # Create figure
        plt.figure(figsize=(12, 10))
        
        # Get node positions using spring layout with more iterations for better layout
        pos = nx.spring_layout(G, k=0.3, iterations=100, seed=42)
        
        # Create custom colormap
        cmap = LinearSegmentedColormap.from_list('cyberops', ['#1f77b4', '#ff7f0e', '#2ca02c'])
        
        # Draw nodes with different colors based on type
        node_types = nx.get_node_attributes(G, 'type')
        network_nodes = [n for n, t in node_types.items() if t == 'network']
        host_nodes = [n for n, t in node_types.items() if t == 'host']
        
        # Draw network node
        nx.draw_networkx_nodes(G, pos, nodelist=network_nodes, 
                              node_color='#ff7f0e', node_size=800, alpha=0.9)
        
        # Draw host nodes
        nx.draw_networkx_nodes(G, pos, nodelist=host_nodes, 
                              node_color='#1f77b4', node_size=350, alpha=0.8)
        
        # Draw edges
        nx.draw_networkx_edges(G, pos, width=1.2, alpha=0.6, edge_color='#aaaaaa')
        
        # Draw labels
        labels = {}
        for node in G.nodes():
            labels[node] = G.nodes[node].get('label', node)
        
        nx.draw_networkx_labels(G, pos, labels, font_size=9, 
                               font_color='white', font_weight='bold')
        
        # Set plot properties
        plt.title(f"Network Map: {', '.join(scan_result['targets'])}", fontsize=16)
        plt.axis('off')
        
        # Add timestamp and metadata
        scan_time = scan_result.get('scan_time', datetime.now().isoformat())
        plt.figtext(0.02, 0.02, f"Scan time: {scan_time}\nTotal hosts: {scan_result.get('total_hosts', 0)}", 
                   fontsize=8, color='white')
        
        # Determine output format and path
        if output_path:
            if not output_path.lower().endswith(f'.{format}'):
                output_path = f"{output_path}.{format}"
            result_path = output_path
        else:
            # Create a temporary file
            with tempfile.NamedTemporaryFile(suffix=f'.{format}', delete=False) as tmp:
                result_path = tmp.name
        
        # Save the figure with higher quality
        plt.savefig(result_path, bbox_inches='tight', dpi=200, format=format, 
                   facecolor='#222222')
        
        plt.close()
        logger.info(f"Network visualization saved to {result_path}")
        return result_path
    
    def export_to_neo4j(self, scan_result: Dict[str, Any], 
                       batch_size: int = 100,
                       create_indexes: bool = True,
                       retry_attempts: int = 3) -> bool:
        """
        Export the network map to Neo4j graph database.
        
        Args:
            scan_result: Result from scan_network
            batch_size: Number of nodes to create in a single transaction
            create_indexes: Whether to create indexes and constraints
            retry_attempts: Number of retry attempts for failed transactions
            
        Returns:
            True if successful, False otherwise
        """
        if not NEO4J_AVAILABLE:
            logger.error("Neo4j client not available, cannot export to graph database")
            return False
        
        try:
            # Get Neo4j configuration from global config
            neo4j_config = self.config.get('neo4j', {})
            neo4j_uri = neo4j_config.get('uri', 'bolt://localhost:7687')
            neo4j_user = neo4j_config.get('username', 'neo4j')
            neo4j_password = neo4j_config.get('password', 'password')
            
            # Create Neo4j client
            client = Neo4jClient(neo4j_uri, neo4j_user, neo4j_password)
            
            # Create constraints and indexes (if they don't exist)
            if create_indexes:
                logger.info("Creating Neo4j constraints and indexes")
                try:
                    # Create constraints for uniqueness
                    client.run_query(
                        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Network) REQUIRE n.cidr IS UNIQUE"
                    )
                    client.run_query(
                        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Host) REQUIRE n.ip IS UNIQUE"
                    )
                    
                    # Create indexes for better query performance
                    client.run_query(
                        "CREATE INDEX IF NOT EXISTS FOR (n:Network) ON (n.scan_time)"
                    )
                    client.run_query(
                        "CREATE INDEX IF NOT EXISTS FOR (n:Host) ON (n.hostname)"
                    )
                    client.run_query(
                        "CREATE INDEX IF NOT EXISTS FOR (n:Host) ON (n.last_seen)"
                    )
                    # Add index for scan_id for faster lookups
                    client.run_query(
                        "CREATE INDEX IF NOT EXISTS FOR (s:Scan) ON (s.id)"
                    )
                except Exception as e:
                    logger.warning(f"Error creating Neo4j constraints/indexes: {str(e)}")
            
            # Add scan metadata
            scan_id = f"scan_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            scan_time = scan_result.get("scan_time", datetime.now().isoformat())
            scan_method = scan_result.get("scan_method", "unknown")
            scan_duration = scan_result.get("scan_duration_ms", 0)
            
            # Create scan node and network nodes in a single transaction
            with client.get_session() as session:
                tx = session.begin_transaction()
                try:
                    # Create scan node to group this scan's results
                    tx.run("""
                        CREATE (s:Scan {id: $id})
                        SET s.time = $time,
                            s.method = $method,
                            s.duration_ms = $duration,
                            s.total_hosts = $total_hosts
                    """, {
                        "id": scan_id,
                        "time": scan_time,
                        "method": scan_method,
                        "duration": scan_duration,
                        "total_hosts": len(scan_result.get("active_hosts", []))
                    })
                    
                    # Create network nodes and link to scan
                    for target in scan_result["targets"]:
                        tx.run("""
                            MERGE (n:Network {cidr: $cidr})
                            SET n.scan_time = $scan_time,
                                n.scan_method = $scan_method,
                                n.last_updated = datetime()
                            WITH n
                            MATCH (s:Scan {id: $scan_id})
                            MERGE (n)-[:SCANNED_IN]->(s)
                        """, {
                            "cidr": target,
                            "scan_time": scan_time,
                            "scan_method": scan_method,
                            "scan_id": scan_id
                        })
                    
                    # Commit the transaction
                    tx.commit()
                    logger.debug("Created scan and network nodes in Neo4j")
                except Exception as e:
                    tx.rollback()
                    logger.error(f"Error creating scan and network nodes: {str(e)}")
                    raise
            
            # Pre-compute network mappings for hosts to improve performance
            network_mappings = {}
            for host in scan_result.get("active_hosts", []):
                host_ip = host.get("ip", "")
                if not host_ip:
                    continue
                    
                # Find which network this host belongs to
                for target in scan_result["targets"]:
                    try:
                        if ipaddress.ip_address(host_ip) in ipaddress.ip_network(target, strict=False):
                            network_mappings[host_ip] = target
                            break
                    except ValueError:
                        pass
                
                # Default to first target if no match found
                if host_ip not in network_mappings and scan_result["targets"]:
                    network_mappings[host_ip] = scan_result["targets"][0]
            
            # Process hosts in batches for better performance
            active_hosts = scan_result.get("active_hosts", [])
            total_hosts = len(active_hosts)
            
            if total_hosts > 0:
                logger.info(f"Exporting {total_hosts} hosts to Neo4j in batches of {batch_size}")
                
                # Prepare Cypher query for bulk insert
                bulk_query = """
                UNWIND $hosts AS host
                MERGE (h:Host {ip: host.ip})
                SET h.hostname = host.hostname,
                    h.mac_address = host.mac,
                    h.last_seen = datetime(),
                    h.discovery_method = host.method
                WITH h, host
                MATCH (n:Network {cidr: host.network})
                MERGE (h)-[:BELONGS_TO]->(n)
                WITH h, host
                MATCH (s:Scan {id: $scan_id})
                MERGE (h)-[:FOUND_IN]->(s)
                """
                
                # Process in batches
                for i in range(0, total_hosts, batch_size):
                    batch = active_hosts[i:i+batch_size]
                    
                    # Prepare batch data
                    host_data = []
                    for host in batch:
                        host_ip = host.get("ip", "")
                        host_data.append({
                            "ip": host_ip,
                            "hostname": host.get("hostname", ""),
                            "mac": host.get("mac_address", ""),
                            "method": host.get("discovery_method", ""),
                            "network": network_mappings.get(host_ip, scan_result["targets"][0] if scan_result["targets"] else "unknown")
                        })
                    
                    # Retry logic for transient errors
                    for attempt in range(retry_attempts):
                        try:
                            # Create a transaction for this batch
                            with client.get_session() as session:
                                # Execute bulk insert
                                session.run(bulk_query, {
                                    "hosts": host_data,
                                    "scan_id": scan_id
                                })
                                
                                logger.debug(f"Exported batch of {len(batch)} hosts to Neo4j (batch {i//batch_size + 1}/{(total_hosts + batch_size - 1)//batch_size})")
                                break  # Success, exit retry loop
                        except Exception as e:
                            if attempt < retry_attempts - 1:
                                # Exponential backoff
                                wait_time = 0.5 * (2 ** attempt)
                                logger.warning(f"Error exporting batch to Neo4j (attempt {attempt+1}/{retry_attempts}): {str(e)}. Retrying in {wait_time:.1f}s...")
                                time.sleep(wait_time)
                            else:
                                logger.error(f"Failed to export batch after {retry_attempts} attempts: {str(e)}")
                                raise
            
            # Add relationships between hosts if they're in the same network
            if total_hosts > 1 and total_hosts <= 1000:  # Only for reasonably sized networks
                try:
                    logger.info("Creating relationships between hosts in the same network")
                    client.run_query("""
                        MATCH (h1:Host)-[:FOUND_IN]->(:Scan {id: $scan_id})
                        MATCH (h2:Host)-[:FOUND_IN]->(:Scan {id: $scan_id})
                        WHERE h1 <> h2
                        AND (h1)-[:BELONGS_TO]->(:Network)<-[:BELONGS_TO]-(h2)
                        MERGE (h1)-[:CONNECTED_TO]->(h2)
                    """, {"scan_id": scan_id})
                except Exception as e:
                    logger.warning(f"Error creating host relationships: {str(e)}")
            
            logger.info(f"Successfully exported scan results to Neo4j (scan_id: {scan_id})")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting to Neo4j: {str(e)}")
            return False


# Command-line interface for testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Parse arguments
    import argparse
    parser = argparse.ArgumentParser(description="Network Mapper")
    parser.add_argument("targets", nargs="+", help="Target networks or IPs (CIDR notation)")
    parser.add_argument("--method", choices=["icmp", "tcp", "arp", "combined"], 
                       default="combined", help="Scan method")
    parser.add_argument("--timeout", type=int, default=1000, 
                       help="Timeout in milliseconds")
    parser.add_argument("--no-resolve", action="store_true", 
                       help="Don't resolve hostnames")
    parser.add_argument("--visualize", action="store_true", 
                       help="Generate visualization")
    parser.add_argument("--output", help="Output file for visualization")
    parser.add_argument("--neo4j", action="store_true", 
                       help="Export to Neo4j")
    args = parser.parse_args()
    
    # Create mapper and scan
    mapper = NetworkMapper()
    
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
    
    # Export to Neo4j if requested
    if args.neo4j:
        try:
            success = mapper.export_to_neo4j(results)
            if success:
                print("Successfully exported to Neo4j")
            else:
                print("Failed to export to Neo4j")
        except Exception as e:
            print(f"Error exporting to Neo4j: {e}")
