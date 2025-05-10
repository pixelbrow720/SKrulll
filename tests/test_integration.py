
"""
Integration tests for SKrulll components.
"""
import unittest
import tempfile
import json
import os
from unittest.mock import patch, MagicMock

from modules.security.attack_vector_mapper import AttackVectorMapper
from modules.security.entry_point_analyzer import EntryPointAnalyzer
from modules.security.reporting_system import ReportingSystem

class TestComponentIntegration(unittest.TestCase):
    """Test cases for component integrations"""

    def setUp(self):
        """Set up test fixtures"""
        # Create mock config
        self.neo4j_config = {
            'uri': 'bolt://localhost:7687',
            'username': 'neo4j',
            'password': 'test'
        }
        
        # Mock data
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
        
    @patch('modules.security.attack_vector_mapper.Neo4jClient')
    def test_attack_path_to_report_flow(self, mock_neo4j):
        """Test the flow from attack path discovery to report generation"""
        # Configure mock Neo4j client
        mock_neo4j_instance = MagicMock()
        mock_neo4j.return_value = mock_neo4j_instance
        
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
        
        mock_neo4j_instance.run_query.return_value = [{'path': mock_path}]
        
        # 1. Set up Attack Vector Mapper
        mapper = AttackVectorMapper(self.neo4j_config)
        
        # 2. Consolidate scan data
        mapper.consolidate_scan_data(self.nmap_results, self.nuclei_results)
        
        # 3. Find attack paths
        paths = mapper.find_attack_paths('192.168.1.1', '192.168.1.2')
        
        # Verify attack paths were found
        self.assertTrue(len(paths) > 0)
        
        # 4. Create vulnerability assessment data
        vuln_data = {
            'vulnerabilities': self.nuclei_results['vulnerabilities'],
            'network_map': {
                'hosts': self.nmap_results['hosts'],
                'attack_paths': [
                    {
                        'source': '192.168.1.1',
                        'target': '192.168.1.2',
                        'risk_score': paths[0].total_risk,
                        'description': paths[0].description,
                        'recommendations': paths[0].recommendations
                    }
                ]
            }
        }
        
        # 5. Generate a report
        reporting = ReportingSystem({})
        
        # Mock the PDF generation
        with patch.object(reporting, '_generate_pdf_report') as mock_pdf:
            mock_pdf.return_value = 'test_report.pdf'
            
            # Generate the report
            report_file = reporting.generate_report(vuln_data, 'pdf')
            
            # Verify report generation was called
            mock_pdf.assert_called_once()
            
            # Verify the report file was returned
            self.assertEqual(report_file, 'test_report.pdf')

if __name__ == '__main__':
    unittest.main()
