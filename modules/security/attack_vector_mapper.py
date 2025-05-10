
"""
Attack Vector Mapper - Consolidates security data into Neo4j graphs for analysis.
"""
import logging
import networkx as nx
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from orchestrator.db.neo4j_client import Neo4jClient

logger = logging.getLogger(__name__)

@dataclass
class AttackPath:
    nodes: List[str]
    total_risk: float
    description: str
    recommendations: List[str]

class AttackVectorMapper:
    
    def __init__(self, neo4j_config: Dict[str, Any]):
        self.neo4j = Neo4jClient(
            neo4j_config.get('uri', 'bolt://0.0.0.0:7687'),
            neo4j_config.get('username', 'neo4j'),
            neo4j_config.get('password', 'password')
        )
        # Cache for storing frequently accessed paths
        self._path_cache = {}
        # Maximum cache size to prevent memory issues
        self._max_cache_size = 1000
    
    def consolidate_scan_data(self, nmap_results: Dict, nuclei_results: Dict) -> None:
        """Consolidate scan results into Neo4j graph"""
        # Create indexes and constraints
        self.neo4j.run_query("""
            CREATE CONSTRAINT IF NOT EXISTS FOR (h:Host) REQUIRE h.ip IS UNIQUE;
            CREATE CONSTRAINT IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE;
        """)
        
        # Add hosts and vulnerabilities
        for host in nmap_results.get('hosts', []):
            # Create host node
            self.neo4j.run_query("""
                MERGE (h:Host {ip: $ip})
                SET h.hostname = $hostname,
                    h.os = $os,
                    h.last_seen = datetime()
            """, {
                'ip': host['ip'],
                'hostname': host.get('hostname'),
                'os': host.get('os')
            })
            
            # Add ports and services
            for port in host.get('ports', []):
                self.neo4j.run_query("""
                    MATCH (h:Host {ip: $ip})
                    MERGE (s:Service {
                        port: $port,
                        name: $service,
                        version: $version
                    })
                    MERGE (h)-[:RUNS]->(s)
                """, {
                    'ip': host['ip'],
                    'port': port['port'],
                    'service': port.get('service'),
                    'version': port.get('version')
                })
        
        # Add vulnerabilities from Nuclei
        for vuln in nuclei_results.get('vulnerabilities', []):
            self.neo4j.run_query("""
                MATCH (h:Host {ip: $ip})
                MERGE (v:Vulnerability {
                    id: $id,
                    name: $name,
                    severity: $severity,
                    cvss: $cvss
                })
                MERGE (h)-[:HAS_VULNERABILITY]->(v)
            """, {
                'ip': vuln['host'],
                'id': vuln['id'],
                'name': vuln['name'],
                'severity': vuln['severity'],
                'cvss': vuln.get('cvss', 0.0)
            })
        
        # Clear cache when new data is added
        self._path_cache = {}
    
    def find_attack_paths(self, start_ip: str, target_ip: str, max_depth: int = 10, max_paths: int = 20) -> List[AttackPath]:
        """
        Find potential attack paths between hosts using an optimized algorithm
        
        Args:
            start_ip: Source IP address
            target_ip: Target IP address
            max_depth: Maximum path depth to search
            max_paths: Maximum number of paths to return
            
        Returns:
            List of attack paths sorted by risk (highest risk first)
        """
        # Check cache first
        cache_key = f"{start_ip}_{target_ip}_{max_depth}_{max_paths}"
        if cache_key in self._path_cache:
            logger.debug(f"Using cached attack paths for {start_ip} to {target_ip}")
            return self._path_cache[cache_key]
        
        # Use a more efficient Cypher query with path pruning and limiting
        query = """
        MATCH path = (start:Host {ip: $start_ip})
        -[:RUNS|HAS_VULNERABILITY|CONNECTS_TO*1..{max_depth}]->
        (end:Host {ip: $target_ip})
        WHERE all(rel IN relationships(path) WHERE rel.disabled <> true)
        WITH path, 
             reduce(weight = 0, r IN relationships(path) | 
                weight + CASE WHEN r.risk IS NOT NULL THEN r.risk ELSE 1 END) AS path_risk
        ORDER BY path_risk DESC
        LIMIT $max_paths
        RETURN path, path_risk
        """
        
        paths = []
        results = self.neo4j.run_query(
            query, 
            {
                'start_ip': start_ip, 
                'target_ip': target_ip,
                'max_depth': max_depth,
                'max_paths': max_paths
            }
        )
        
        for record in results:
            path = record['path']
            path_risk = record['path_risk']
            nodes = [node['ip'] for node in path.nodes if 'ip' in node]
            
            attack_path = AttackPath(
                nodes=nodes,
                total_risk=float(path_risk),
                description=self._generate_path_description(path),
                recommendations=self._generate_recommendations(path)
            )
            paths.append(attack_path)
        
        # Sort paths by risk score (highest first)
        paths.sort(key=lambda p: p.total_risk, reverse=True)
        
        # Cache the result
        if len(self._path_cache) >= self._max_cache_size:
            # Remove a random item if cache is full
            self._path_cache.pop(next(iter(self._path_cache)))
        self._path_cache[cache_key] = paths
        
        return paths
    
    def build_graph_from_neo4j(self, query_limit: int = 1000) -> nx.DiGraph:
        """
        Build a NetworkX graph from Neo4j data for advanced analysis
        
        This method queries the Neo4j database and constructs a NetworkX graph
        that can be used for various graph algorithms and visualizations that
        may not be easily implemented in Cypher.
        
        Args:
            query_limit: Maximum number of nodes to retrieve from Neo4j
            
        Returns:
            NetworkX DiGraph containing hosts, services, and vulnerabilities
        """
        # Create a new directed graph
        graph = nx.DiGraph()
        
        # Get hosts
        host_query = """
        MATCH (h:Host)
        RETURN h.ip as ip, h.hostname as hostname, h.os as os
        LIMIT $limit
        """
        hosts = self.neo4j.run_query(host_query, {'limit': query_limit})
        
        # Add host nodes
        for host in hosts:
            graph.add_node(
                host['ip'], 
                type='host',
                hostname=host['hostname'],
                os=host['os']
            )
        
        # Get services and their relationships to hosts
        service_query = """
        MATCH (h:Host)-[:RUNS]->(s:Service)
        RETURN h.ip as host_ip, s.port as port, s.name as name, 
               s.version as version
        LIMIT $limit
        """
        services = self.neo4j.run_query(service_query, {'limit': query_limit})
        
        # Add service nodes and edges
        for service in services:
            service_id = f"{service['host_ip']}:{service['port']}"
            graph.add_node(
                service_id,
                type='service',
                port=service['port'],
                name=service['name'],
                version=service['version']
            )
            graph.add_edge(service['host_ip'], service_id, type='RUNS')
        
        # Get vulnerabilities and their relationships to hosts
        vuln_query = """
        MATCH (h:Host)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        RETURN h.ip as host_ip, v.id as id, v.name as name, 
               v.severity as severity, v.cvss as cvss
        LIMIT $limit
        """
        vulns = self.neo4j.run_query(vuln_query, {'limit': query_limit})
        
        # Add vulnerability nodes and edges
        for vuln in vulns:
            graph.add_node(
                vuln['id'],
                type='vulnerability',
                name=vuln['name'],
                severity=vuln['severity'],
                cvss=vuln['cvss']
            )
            graph.add_edge(vuln['host_ip'], vuln['id'], type='HAS_VULNERABILITY')
        
        # Get host-to-host connections
        connection_query = """
        MATCH (h1:Host)-[:CONNECTS_TO]->(h2:Host)
        RETURN h1.ip as source_ip, h2.ip as target_ip
        LIMIT $limit
        """
        connections = self.neo4j.run_query(connection_query, {'limit': query_limit})
        
        # Add connection edges
        for conn in connections:
            graph.add_edge(
                conn['source_ip'], 
                conn['target_ip'], 
                type='CONNECTS_TO'
            )
        
        logger.info(f"Built NetworkX graph with {graph.number_of_nodes()} nodes and {graph.number_of_edges()} edges")
        return graph
    
    def find_critical_nodes(self, threshold: float = 7.0) -> List[Dict[str, Any]]:
        """
        Find critical nodes in the attack graph that could be part of multiple attack paths
        
        Args:
            threshold: CVSS score threshold for considering a node critical
            
        Returns:
            List of critical nodes with their properties
        """
        query = """
        MATCH (h:Host)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        WHERE v.cvss >= $threshold
        WITH h, count(v) as vuln_count
        MATCH (h)-[:RUNS]->(s:Service)
        WITH h, vuln_count, count(s) as service_count
        MATCH p = shortestPath((h)-[:CONNECTS_TO*]->(:Host))
        WHERE length(p) > 0
        WITH h, vuln_count, service_count, count(p) as path_count
        WHERE path_count > 1
        RETURN h.ip as ip, h.hostname as hostname, 
               vuln_count, service_count, path_count,
               vuln_count * service_count * path_count as criticality
        ORDER BY criticality DESC
        LIMIT 10
        """
        
        results = self.neo4j.run_query(query, {'threshold': threshold})
        critical_nodes = []
        
        for record in results:
            critical_nodes.append({
                'ip': record['ip'],
                'hostname': record['hostname'],
                'vulnerability_count': record['vuln_count'],
                'service_count': record['service_count'],
                'path_count': record['path_count'],
                'criticality_score': record['criticality']
            })
        
        return critical_nodes
    
    def _generate_path_description(self, path) -> str:
        """Generate a human-readable description of an attack path"""
        steps = []
        for i, node in enumerate(path.nodes[:-1]):
            next_node = path.nodes[i + 1]
            rel = path.relationships[i]
            
            if 'ip' in node and 'ip' in next_node:
                # Add more context about the relationship
                rel_type = rel.type
                rel_props = {k: v for k, v in rel.items() if k != 'risk'}
                
                if rel_props:
                    props_str = ", ".join(f"{k}: {v}" for k, v in rel_props.items())
                    steps.append(f"From {node['ip']} to {next_node['ip']} via {rel_type} ({props_str})")
                else:
                    steps.append(f"From {node['ip']} to {next_node['ip']} via {rel_type}")
        
        return " -> ".join(steps)
    
    def _generate_recommendations(self, path) -> List[str]:
        """Generate security recommendations for an attack path"""
        recommendations = set()  # Use a set to avoid duplicate recommendations
        
        for node in path.nodes:
            if 'vulnerability' in node.labels:
                severity = node.get('severity', 'unknown').lower()
                cvss = node.get('cvss', 0.0)
                
                # Prioritize recommendations based on severity
                if severity == 'critical' or cvss >= 9.0:
                    recommendations.add(f"CRITICAL: Patch vulnerability {node['name']} immediately on affected systems")
                elif severity == 'high' or cvss >= 7.0:
                    recommendations.add(f"HIGH: Patch vulnerability {node['name']} as soon as possible")
                else:
                    recommendations.add(f"Patch vulnerability {node['name']} on affected systems")
            
            elif 'service' in node.labels and node.get('version'):
                service_name = node.get('name', 'unknown')
                port = node.get('port', 'unknown')
                recommendations.add(f"Update {service_name} service (port {port}) to latest version")
                
                # Add firewall recommendation
                recommendations.add(f"Review firewall rules for port {port} and limit access if possible")
        
        # Add general recommendations
        if len(path.nodes) > 3:
            recommendations.add("Implement network segmentation to break potential attack paths")
        
        return sorted(list(recommendations))
    
    def analyze_graph_centrality(self, include_services: bool = False, include_vulnerabilities: bool = False) -> Dict[str, Dict[str, float]]:
        """
        Analyze the attack graph using various centrality measures
        
        This method builds a NetworkX graph from Neo4j data and calculates
        different centrality measures to identify the most important nodes
        in the network from a security perspective.
        
        Args:
            include_services: Whether to include service nodes in the analysis
            include_vulnerabilities: Whether to include vulnerability nodes in the analysis
            
        Returns:
            Dictionary mapping node IDs to their centrality scores
        """
        # Build the graph from Neo4j data
        graph = self.build_graph_from_neo4j()
        
        # Filter nodes based on parameters
        if not include_services and not include_vulnerabilities:
            # Only keep host nodes
            nodes_to_remove = [n for n, attrs in graph.nodes(data=True) 
                              if attrs.get('type') != 'host']
            graph.remove_nodes_from(nodes_to_remove)
        elif not include_services:
            # Keep hosts and vulnerabilities
            nodes_to_remove = [n for n, attrs in graph.nodes(data=True) 
                              if attrs.get('type') == 'service']
            graph.remove_nodes_from(nodes_to_remove)
        elif not include_vulnerabilities:
            # Keep hosts and services
            nodes_to_remove = [n for n, attrs in graph.nodes(data=True) 
                              if attrs.get('type') == 'vulnerability']
            graph.remove_nodes_from(nodes_to_remove)
        
        # Calculate various centrality measures
        centrality_measures = {}
        
        # Degree centrality - nodes with many connections
        try:
            centrality_measures['degree'] = nx.degree_centrality(graph)
        except Exception as e:
            logger.warning(f"Could not calculate degree centrality: {e}")
            centrality_measures['degree'] = {}
        
        # Betweenness centrality - nodes that act as bridges
        try:
            centrality_measures['betweenness'] = nx.betweenness_centrality(graph)
        except Exception as e:
            logger.warning(f"Could not calculate betweenness centrality: {e}")
            centrality_measures['betweenness'] = {}
        
        # Closeness centrality - nodes that can quickly reach others
        try:
            centrality_measures['closeness'] = nx.closeness_centrality(graph)
        except Exception as e:
            logger.warning(f"Could not calculate closeness centrality: {e}")
            centrality_measures['closeness'] = {}
        
        # Eigenvector centrality - nodes connected to important nodes
        try:
            centrality_measures['eigenvector'] = nx.eigenvector_centrality_numpy(graph)
        except Exception as e:
            logger.warning(f"Could not calculate eigenvector centrality: {e}")
            centrality_measures['eigenvector'] = {}
        
        # Combine all measures into a single result
        result = {}
        for node in graph.nodes():
            result[node] = {
                'type': graph.nodes[node].get('type', 'unknown'),
                'degree': centrality_measures['degree'].get(node, 0.0),
                'betweenness': centrality_measures['betweenness'].get(node, 0.0),
                'closeness': centrality_measures['closeness'].get(node, 0.0),
                'eigenvector': centrality_measures['eigenvector'].get(node, 0.0),
                # Combined score (weighted average)
                'combined_score': (
                    centrality_measures['degree'].get(node, 0.0) * 0.25 +
                    centrality_measures['betweenness'].get(node, 0.0) * 0.35 +
                    centrality_measures['closeness'].get(node, 0.0) * 0.15 +
                    centrality_measures['eigenvector'].get(node, 0.0) * 0.25
                )
            }
        
        # Sort by combined score and return
        return {k: v for k, v in sorted(
            result.items(), 
            key=lambda item: item[1]['combined_score'], 
            reverse=True
        )}
    
    def detect_network_communities(self, output_file: Optional[str] = None) -> Dict[str, List[str]]:
        """
        Detect communities in the network using the Louvain algorithm
        
        This method identifies clusters of nodes that are more densely connected
        to each other than to the rest of the network. These communities can
        represent distinct attack surfaces or security domains.
        
        Args:
            output_file: Optional path to save a visualization of the communities
            
        Returns:
            Dictionary mapping community IDs to lists of node IDs in that community
        """
        try:
            # Import community detection algorithm
            import community as community_louvain
        except ImportError:
            logger.error("Could not import python-louvain package. Install with: pip install python-louvain")
            return {}
        
        # Build the graph from Neo4j data
        graph = self.build_graph_from_neo4j()
        
        # Convert to undirected graph for community detection
        undirected_graph = graph.to_undirected()
        
        # Apply the Louvain method for community detection
        partition = community_louvain.best_partition(undirected_graph)
        
        # Group nodes by community
        communities = {}
        for node, community_id in partition.items():
            if community_id not in communities:
                communities[community_id] = []
            communities[community_id].append(node)
        
        # Sort communities by size (largest first)
        sorted_communities = {
            k: v for k, v in sorted(
                communities.items(), 
                key=lambda item: len(item[1]), 
                reverse=True
            )
        }
        
        # Generate visualization if requested
        if output_file:
            self._visualize_communities(graph, partition, output_file)
        
        return sorted_communities
    
    def _visualize_communities(self, graph: nx.Graph, partition: Dict[str, int], output_file: str) -> None:
        """
        Generate a visualization of network communities
        
        Args:
            graph: NetworkX graph to visualize
            partition: Dictionary mapping node IDs to community IDs
            output_file: Path to save the visualization image
        """
        import matplotlib.pyplot as plt
        import matplotlib.cm as cm
        
        # Set up the figure
        plt.figure(figsize=(14, 10))
        
        # Use a more deterministic layout for larger graphs
        if len(graph) > 20:
            pos = nx.kamada_kawai_layout(graph)
        else:
            pos = nx.spring_layout(graph, seed=42)
        
        # Get number of communities
        num_communities = len(set(partition.values()))
        
        # Choose a colormap with distinct colors
        cmap = cm.get_cmap('tab20', max(num_communities, 20))
        
        # Draw nodes colored by community
        for community_id in set(partition.values()):
            # Get nodes in this community
            nodes = [node for node in graph.nodes() if partition[node] == community_id]
            
            # Draw nodes
            nx.draw_networkx_nodes(
                graph, pos,
                nodelist=nodes,
                node_color=[cmap(community_id)],
                node_size=300,
                alpha=0.8,
                label=f"Community {community_id}"
            )
        
        # Draw edges with low opacity to reduce visual clutter
        nx.draw_networkx_edges(graph, pos, alpha=0.2)
        
        # Draw node labels for important nodes only (to reduce clutter)
        # For example, only label nodes with high degree
        important_nodes = [node for node, degree in graph.degree() if degree > 2]
        nx.draw_networkx_labels(
            graph, pos,
            labels={node: node for node in important_nodes},
            font_size=8
        )
        
        plt.title("Network Communities")
        plt.axis('off')
        
        # Add legend with reasonable size
        if num_communities <= 10:  # Only show legend for a reasonable number of communities
            plt.legend(scatterpoints=1, loc='upper right')
        
        plt.tight_layout()
        plt.savefig(output_file, dpi=300)
        plt.close()
        
        logger.info(f"Community visualization saved to {output_file}")
    
    def visualize_attack_paths(self, paths: List[AttackPath], output_file: str) -> None:
        """
        Generate a visualization of attack paths
        
        This method creates a new NetworkX graph from the provided attack paths
        and visualizes them, with different colors and sizes to represent
        different types of nodes and risk levels.
        
        Args:
            paths: List of AttackPath objects to visualize
            output_file: Path to save the visualization image
        """
        import matplotlib.pyplot as plt
        import matplotlib.patches as mpatches
        
        # Create a new graph for visualization
        viz_graph = nx.DiGraph()
        
        # Add all nodes and edges from paths
        for path in paths:
            for i in range(len(path.nodes) - 1):
                source = path.nodes[i]
                target = path.nodes[i + 1]
                
                # Add nodes with attributes
                if source not in viz_graph:
                    viz_graph.add_node(source, type='host')
                if target not in viz_graph:
                    viz_graph.add_node(target, type='host')
                
                # Add edge with risk attribute
                if not viz_graph.has_edge(source, target):
                    viz_graph.add_edge(source, target, risk=0, paths=[])
                
                # Update edge attributes
                viz_graph[source][target]['risk'] += path.total_risk / len(path.nodes)
                viz_graph[source][target]['paths'].append(path)
        
        plt.figure(figsize=(14, 10))
        
        # Use a more deterministic layout for larger graphs
        if len(viz_graph) > 20:
            pos = nx.kamada_kawai_layout(viz_graph)
        else:
            pos = nx.spring_layout(viz_graph, seed=42)
        
        # Node color based on type or criticality
        node_colors = []
        for node in viz_graph.nodes():
            # Check if this is a start or end node in any path
            is_start = any(node == path.nodes[0] for path in paths)
            is_end = any(node == path.nodes[-1] for path in paths)
            
            if is_start:
                node_colors.append('green')
            elif is_end:
                node_colors.append('red')
            else:
                node_colors.append('lightblue')
        
        # Draw nodes with different sizes based on their degree
        node_sizes = [300 + 100 * viz_graph.degree(node) for node in viz_graph.nodes()]
        nx.draw_networkx_nodes(viz_graph, pos, node_color=node_colors, node_size=node_sizes, alpha=0.8)
        nx.draw_networkx_labels(viz_graph, pos, font_size=8)
        
        # Draw edges with width based on risk and color based on path
        edge_colors = []
        edge_widths = []
        
        for u, v, data in viz_graph.edges(data=True):
            risk = data.get('risk', 1.0)
            edge_widths.append(1 + risk / 2)  # Scale width based on risk
            
            # Color based on risk level
            if risk > 7.0:
                edge_colors.append('red')
            elif risk > 4.0:
                edge_colors.append('orange')
            else:
                edge_colors.append('blue')
        
        nx.draw_networkx_edges(viz_graph, pos, width=edge_widths, edge_color=edge_colors, 
                             alpha=0.7, arrowsize=15)
        
        # Add legend
        legend_elements = [
            mpatches.Patch(color='green', label='Source Hosts'),
            mpatches.Patch(color='red', label='Target Hosts'),
            mpatches.Patch(color='lightblue', label='Intermediate Hosts'),
            mpatches.Patch(color='red', label='High Risk Path'),
            mpatches.Patch(color='orange', label='Medium Risk Path'),
            mpatches.Patch(color='blue', label='Low Risk Path')
        ]
        plt.legend(handles=legend_elements, loc='upper right')
        
        plt.title("Attack Vector Map - Prioritized Paths")
        plt.axis('off')
        plt.tight_layout()
        plt.savefig(output_file, dpi=300)
        plt.close()
        
        logger.info(f"Attack vector visualization saved to {output_file}")
