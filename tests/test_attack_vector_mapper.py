"""
Unit tests for the Attack Vector Mapper module.

This module contains tests for the AttackVectorMapper class, which is responsible
for mapping potential attack vectors in a target system.
"""
import unittest
from unittest.mock import patch, MagicMock
import json
import os
import sys

# Add project root to path
sys.path.append('.')

from modules.security.attack_vector_mapper import AttackVectorMapper, AttackPath


class TestAttackVectorMapper(unittest.TestCase):
    """Test cases for the AttackVectorMapper class"""

    def setUp(self):
        """Set up test fixtures"""
        self.neo4j_config = {
            'uri': 'bolt://localhost:7687',
            'username': 'neo4j',
            'password': 'test'
        }
        
        # Create the mapper with a mock Neo4j client
        with patch('modules.security.attack_vector_mapper.Neo4jClient') as mock_neo4j:
            self.mock_neo4j_instance = MagicMock()
            mock_neo4j.return_value = self.mock_neo4j_instance
            self.mapper = AttackVectorMapper(self.neo4j_config)
        
        # Sample data for tests
        self.nmap_results = {
            'hosts': [
                {
                    'ip': '192.168.1.1',
                    'hostname': 'web-server',
                    'os': 'Ubuntu 20.04',
                    'ports': [
                        {'port': 80, 'service': 'http', 'version': 'Apache 2.4.41'},
                        {'port': 443, 'service': 'https', 'version': 'Apache 2.4.41'},
                        {'port': 22, 'service': 'ssh', 'version': 'OpenSSH 8.2p1'}
                    ]
                },
                {
                    'ip': '192.168.1.2',
                    'hostname': 'db-server',
                    'os': 'CentOS 8',
                    'ports': [
                        {'port': 3306, 'service': 'mysql', 'version': 'MySQL 8.0.21'},
                        {'port': 22, 'service': 'ssh', 'version': 'OpenSSH 8.0p1'}
                    ]
                }
            ]
        }
        
        self.nuclei_results = {
            'vulnerabilities': [
                {
                    'host': '192.168.1.1',
                    'id': 'CVE-2021-44228',
                    'name': 'Log4j RCE',
                    'severity': 'critical',
                    'cvss': 10.0
                },
                {
                    'host': '192.168.1.2',
                    'id': 'CVE-2021-3449',
                    'name': 'OpenSSL DoS',
                    'severity': 'medium',
                    'cvss': 5.9
                }
            ]
        }

    def test_init(self):
        """Test initialization of the AttackVectorMapper"""
        # Verify that the Neo4j client was initialized with the correct config
        self.assertEqual(self.mapper.neo4j_config, self.neo4j_config)
        self.assertIsNotNone(self.mapper.neo4j_client)

    def test_consolidate_scan_data(self):
        """Test consolidating scan data into the graph database"""
        # Set up mock for the Neo4j client
        self.mock_neo4j_instance.run_query.return_value = []
        
        # Call the method
        self.mapper.consolidate_scan_data(self.nmap_results, self.nuclei_results)
        
        # Verify that the Neo4j client was called with the correct queries
        self.assertEqual(self.mock_neo4j_instance.run_query.call_count, 7)
        
        # Check that hosts were added
        host_query_calls = [
            call for call in self.mock_neo4j_instance.run_query.call_args_list 
            if "CREATE (h:Host" in call[0][0]
        ]
        self.assertEqual(len(host_query_calls), 2)
        
        # Check that vulnerabilities were added
        vuln_query_calls = [
            call for call in self.mock_neo4j_instance.run_query.call_args_list 
            if "CREATE (v:Vulnerability" in call[0][0]
        ]
        self.assertEqual(len(vuln_query_calls), 2)
        
        # Check that relationships were created
        rel_query_calls = [
            call for call in self.mock_neo4j_instance.run_query.call_args_list 
            if "MATCH (h:Host" in call[0][0] and "MATCH (v:Vulnerability" in call[0][0]
        ]
        self.assertEqual(len(rel_query_calls), 2)

    def test_find_attack_paths(self):
        """Test finding attack paths between hosts"""
        # Create a fake path between hosts
        mock_path = MagicMock()
        mock_path.nodes = [
            {'ip': '192.168.1.1', 'hostname': 'web-server'},
            {'vulnerability': {'name': 'Log4j RCE', 'cvss': 10.0}},
            {'ip': '192.168.1.2', 'hostname': 'db-server'}
        ]
        mock_path.relationships = [
            {'risk': 0.9, 'type': 'HAS_VULNERABILITY'},
            {'risk': 0.8, 'type': 'CONNECTS_TO'}
        ]
        
        # Set up mock for the Neo4j client
        self.mock_neo4j_instance.run_query.return_value = [{'path': mock_path}]
        
        # Call the method
        paths = self.mapper.find_attack_paths('192.168.1.1', '192.168.1.2')
        
        # Verify that the Neo4j client was called with the correct query
        self.mock_neo4j_instance.run_query.assert_called_once()
        query_args = self.mock_neo4j_instance.run_query.call_args[0]
        self.assertIn("MATCH p = (source:Host)-[*1..10]-(target:Host)", query_args[0])
        self.assertIn("source.ip = $source_ip", query_args[0])
        self.assertIn("target.ip = $target_ip", query_args[0])
        self.assertEqual(query_args[1]['source_ip'], '192.168.1.1')
        self.assertEqual(query_args[1]['target_ip'], '192.168.1.2')
        
        # Verify the returned paths
        self.assertEqual(len(paths), 1)
        self.assertIsInstance(paths[0], AttackPath)
        self.assertEqual(paths[0].source, '192.168.1.1')
        self.assertEqual(paths[0].target, '192.168.1.2')
        self.assertGreater(paths[0].total_risk, 0)
        self.assertIsNotNone(paths[0].description)
        self.assertIsNotNone(paths[0].recommendations)

    def test_find_attack_paths_no_paths(self):
        """Test finding attack paths when no paths exist"""
        # Set up mock for the Neo4j client
        self.mock_neo4j_instance.run_query.return_value = []
        
        # Call the method
        paths = self.mapper.find_attack_paths('192.168.1.1', '192.168.1.3')
        
        # Verify the returned paths
        self.assertEqual(len(paths), 0)

    def test_find_critical_vulnerabilities(self):
        """Test finding critical vulnerabilities"""
        # Set up mock for the Neo4j client
        self.mock_neo4j_instance.run_query.return_value = [
            {'v': {'name': 'Log4j RCE', 'cvss': 10.0, 'id': 'CVE-2021-44228'}, 'h': {'ip': '192.168.1.1', 'hostname': 'web-server'}},
            {'v': {'name': 'SQL Injection', 'cvss': 9.8, 'id': 'CVE-2020-1234'}, 'h': {'ip': '192.168.1.2', 'hostname': 'db-server'}}
        ]
        
        # Call the method
        vulns = self.mapper.find_critical_vulnerabilities()
        
        # Verify that the Neo4j client was called with the correct query
        self.mock_neo4j_instance.run_query.assert_called_once()
        query_args = self.mock_neo4j_instance.run_query.call_args[0]
        self.assertIn("MATCH (h:Host)-[:HAS_VULNERABILITY]->(v:Vulnerability)", query_args[0])
        self.assertIn("v.cvss >= 7.0", query_args[0])
        
        # Verify the returned vulnerabilities
        self.assertEqual(len(vulns), 2)
        self.assertEqual(vulns[0]['vulnerability']['name'], 'Log4j RCE')
        self.assertEqual(vulns[0]['host']['ip'], '192.168.1.1')
        self.assertEqual(vulns[1]['vulnerability']['name'], 'SQL Injection')
        self.assertEqual(vulns[1]['host']['ip'], '192.168.1.2')

    def test_find_exposed_services(self):
        """Test finding exposed services"""
        # Set up mock for the Neo4j client
        self.mock_neo4j_instance.run_query.return_value = [
            {'h': {'ip': '192.168.1.1', 'hostname': 'web-server'}, 's': {'port': 80, 'service': 'http', 'version': 'Apache 2.4.41'}},
            {'h': {'ip': '192.168.1.1', 'hostname': 'web-server'}, 's': {'port': 443, 'service': 'https', 'version': 'Apache 2.4.41'}},
            {'h': {'ip': '192.168.1.2', 'hostname': 'db-server'}, 's': {'port': 3306, 'service': 'mysql', 'version': 'MySQL 8.0.21'}}
        ]
        
        # Call the method
        services = self.mapper.find_exposed_services()
        
        # Verify that the Neo4j client was called with the correct query
        self.mock_neo4j_instance.run_query.assert_called_once()
        query_args = self.mock_neo4j_instance.run_query.call_args[0]
        self.assertIn("MATCH (h:Host)-[:RUNS]->(s:Service)", query_args[0])
        
        # Verify the returned services
        self.assertEqual(len(services), 3)
        self.assertEqual(services[0]['host']['ip'], '192.168.1.1')
        self.assertEqual(services[0]['service']['port'], 80)
        self.assertEqual(services[1]['service']['port'], 443)
        self.assertEqual(services[2]['host']['ip'], '192.168.1.2')
        self.assertEqual(services[2]['service']['port'], 3306)

    def test_calculate_risk_score(self):
        """Test calculating risk scores"""
        # Test with a critical vulnerability
        risk_score = self.mapper.calculate_risk_score(10.0, 'critical')
        self.assertGreaterEqual(risk_score, 0.9)
        
        # Test with a medium vulnerability
        risk_score = self.mapper.calculate_risk_score(5.9, 'medium')
        self.assertGreaterEqual(risk_score, 0.5)
        self.assertLess(risk_score, 0.9)
        
        # Test with a low vulnerability
        risk_score = self.mapper.calculate_risk_score(3.2, 'low')
        self.assertGreaterEqual(risk_score, 0.1)
        self.assertLess(risk_score, 0.5)

    def test_generate_attack_path_description(self):
        """Test generating attack path descriptions"""
        # Create a sample attack path
        path = AttackPath(
            nodes=['192.168.1.1', 'Log4j RCE', '192.168.1.2'],
            edges=['HAS_VULNERABILITY', 'CONNECTS_TO'],
            source='192.168.1.1',
            target='192.168.1.2',
            total_risk=0.9
        )
        
        # Call the method
        description = self.mapper.generate_attack_path_description(path)
        
        # Verify the description
        self.assertIsInstance(description, str)
        self.assertIn('192.168.1.1', description)
        self.assertIn('Log4j RCE', description)
        self.assertIn('192.168.1.2', description)

    def test_generate_recommendations(self):
        """Test generating recommendations"""
        # Create a sample attack path
        path = AttackPath(
            nodes=['192.168.1.1', 'Log4j RCE', '192.168.1.2'],
            edges=['HAS_VULNERABILITY', 'CONNECTS_TO'],
            source='192.168.1.1',
            target='192.168.1.2',
            total_risk=0.9
        )
        
        # Call the method
        recommendations = self.mapper.generate_recommendations(path)
        
        # Verify the recommendations
        self.assertIsInstance(recommendations, list)
        self.assertGreater(len(recommendations), 0)
        # Check that at least one recommendation mentions the vulnerability
        self.assertTrue(any('Log4j' in rec for rec in recommendations))

    def test_export_graph(self):
        """Test exporting the graph to a file"""
        # Create a temporary file path
        temp_file = "test_graph.json"
        
        # Set up mock for the Neo4j client
        self.mock_neo4j_instance.run_query.return_value = [
            {'h': {'ip': '192.168.1.1', 'hostname': 'web-server'}},
            {'h': {'ip': '192.168.1.2', 'hostname': 'db-server'}}
        ]
        
        try:
            # Call the method
            file_path = self.mapper.export_graph(temp_file)
            
            # Verify that the Neo4j client was called with the correct query
            self.mock_neo4j_instance.run_query.assert_called_once()
            query_args = self.mock_neo4j_instance.run_query.call_args[0]
            self.assertIn("MATCH (n)", query_args[0])
            
            # Verify the returned file path
            self.assertEqual(file_path, temp_file)
            self.assertTrue(os.path.exists(temp_file))
            
            # Check that the file contains valid JSON
            with open(temp_file, 'r') as f:
                graph_data = json.load(f)
            
            self.assertIsInstance(graph_data, dict)
            self.assertIn('nodes', graph_data)
            self.assertIn('relationships', graph_data)
            
        finally:
            # Clean up
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def test_attack_path_class(self):
        """Test the AttackPath class"""
        # Create an attack path
        path = AttackPath(
            nodes=['192.168.1.1', 'Log4j RCE', '192.168.1.2'],
            edges=['HAS_VULNERABILITY', 'CONNECTS_TO'],
            source='192.168.1.1',
            target='192.168.1.2',
            total_risk=0.9
        )
        
        # Verify the properties
        self.assertEqual(path.nodes, ['192.168.1.1', 'Log4j RCE', '192.168.1.2'])
        self.assertEqual(path.edges, ['HAS_VULNERABILITY', 'CONNECTS_TO'])
        self.assertEqual(path.source, '192.168.1.1')
        self.assertEqual(path.target, '192.168.1.2')
        self.assertEqual(path.total_risk, 0.9)
        
        # Test the string representation
        str_rep = str(path)
        self.assertIn('192.168.1.1', str_rep)
        self.assertIn('Log4j RCE', str_rep)
        self.assertIn('192.168.1.2', str_rep)
        
        # Test the dictionary representation
        dict_rep = path.to_dict()
        self.assertIsInstance(dict_rep, dict)
        self.assertEqual(dict_rep['source'], '192.168.1.1')
        self.assertEqual(dict_rep['target'], '192.168.1.2')
        self.assertEqual(dict_rep['total_risk'], 0.9)
        self.assertEqual(dict_rep['nodes'], ['192.168.1.1', 'Log4j RCE', '192.168.1.2'])
        self.assertEqual(dict_rep['edges'], ['HAS_VULNERABILITY', 'CONNECTS_TO'])


if __name__ == '__main__':
    unittest.main()
