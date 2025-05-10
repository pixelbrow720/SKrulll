"""
End-to-End tests for SKrulll.

This module contains end-to-end tests that verify the complete functionality
of the system by simulating real user scenarios and workflows.
"""
import unittest
import os
import sys
import json
import time
import requests
from unittest.mock import patch, MagicMock

# Add project root to path
sys.path.append('.')

from web.app import create_app
from orchestrator.cli import cli_app
from modules.security.attack_vector_mapper import AttackVectorMapper
from modules.security.vulnerability_scanner import VulnerabilityScanner
from modules.osint.domain_recon import DomainRecon
from modules.security.reporting_system import ReportingSystem


class TestEndToEndWorkflows(unittest.TestCase):
    """Test end-to-end workflows that simulate real user scenarios"""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures that are used for all tests"""
        # Create a test Flask app
        cls.app = create_app(debug=True)
        cls.app.config['TESTING'] = True
        cls.app.config['WTF_CSRF_ENABLED'] = False
        cls.client = cls.app.test_client()
        
        # Mock configuration
        cls.config = {
            'database': {
                'neo4j': {
                    'uri': 'bolt://localhost:7687',
                    'username': 'neo4j',
                    'password': 'test'
                },
                'postgresql': {
                    'host': 'localhost',
                    'port': 5432,
                    'database': 'test_db',
                    'user': 'test_user',
                    'password': 'test_password'
                }
            },
            'reporting': {
                'output_dir': '/tmp/skrulll_reports',
                'company_name': 'Test Company',
                'logo_path': 'static/img/logo.png'
            }
        }
        
        # Ensure the reports directory exists
        os.makedirs(cls.config['reporting']['output_dir'], exist_ok=True)

    def setUp(self):
        """Set up test fixtures for each test"""
        # Create mock data for tests
        self.test_domain = "example.com"
        self.test_ip = "192.168.1.1"
        self.test_network = "192.168.1.0/24"
        
        # Mock scan results
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

    @patch('modules.security.vulnerability_scanner.VulnerabilityScanner.scan')
    @patch('modules.osint.domain_recon.DomainRecon.scan')
    @patch('modules.security.attack_vector_mapper.Neo4jClient')
    def test_full_security_assessment_workflow(self, mock_neo4j, mock_domain_scan, mock_vuln_scan):
        """Test a complete security assessment workflow from recon to reporting"""
        # 1. Set up mocks
        # Mock domain recon results
        mock_domain_scan.return_value = {
            'domain': self.test_domain,
            'ip_addresses': ['192.168.1.1', '192.168.1.2'],
            'nameservers': ['ns1.example.com', 'ns2.example.com'],
            'mx_records': ['mail.example.com'],
            'subdomains': ['www.example.com', 'api.example.com', 'mail.example.com']
        }
        
        # Mock vulnerability scan results
        mock_vuln_scan.return_value = self.nuclei_results
        
        # Mock Neo4j client for attack vector mapping
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
        
        # 2. Execute the workflow
        
        # Step 1: Domain reconnaissance
        domain_recon = DomainRecon()
        recon_results = domain_recon.scan(self.test_domain)
        
        # Verify recon results
        self.assertEqual(recon_results['domain'], self.test_domain)
        self.assertIn('192.168.1.1', recon_results['ip_addresses'])
        
        # Step 2: Vulnerability scanning
        vuln_scanner = VulnerabilityScanner()
        vuln_results = vuln_scanner.scan(recon_results['ip_addresses'])
        
        # Verify vulnerability results
        self.assertEqual(len(vuln_results['vulnerabilities']), 2)
        self.assertEqual(vuln_results['vulnerabilities'][0]['id'], 'CVE-2021-44228')
        
        # Step 3: Attack vector mapping
        mapper = AttackVectorMapper(self.config['database']['neo4j'])
        mapper.consolidate_scan_data(self.nmap_results, vuln_results)
        attack_paths = mapper.find_attack_paths('192.168.1.1', '192.168.1.2')
        
        # Verify attack paths
        self.assertTrue(len(attack_paths) > 0)
        self.assertEqual(attack_paths[0].nodes[0], '192.168.1.1')
        self.assertEqual(attack_paths[0].nodes[-1], '192.168.1.2')
        
        # Step 4: Report generation
        reporting = ReportingSystem(self.config['reporting'])
        
        # Prepare report data
        report_data = {
            'vulnerabilities': vuln_results['vulnerabilities'],
            'network_map': {
                'hosts': self.nmap_results['hosts'],
                'attack_paths': [
                    {
                        'source': '192.168.1.1',
                        'target': '192.168.1.2',
                        'risk_score': attack_paths[0].total_risk,
                        'description': attack_paths[0].description,
                        'recommendations': attack_paths[0].recommendations
                    }
                ]
            },
            'domain_info': recon_results
        }
        
        # Mock the PDF generation
        with patch.object(reporting, '_generate_pdf_report') as mock_pdf:
            mock_pdf.return_value = os.path.join(self.config['reporting']['output_dir'], 'test_report.pdf')
            
            # Generate the report
            report_file = reporting.generate_report(report_data, 'pdf')
            
            # Verify report generation was called
            mock_pdf.assert_called_once()
            
            # Verify the report file was returned
            self.assertTrue(report_file.endswith('test_report.pdf'))

    @patch('requests.post')
    @patch('requests.get')
    def test_web_api_workflow(self, mock_get, mock_post):
        """Test the web API workflow for creating and monitoring tasks"""
        # Mock API responses
        mock_login_response = MagicMock()
        mock_login_response.status_code = 200
        mock_login_response.json.return_value = {
            'status': 'success',
            'message': 'Login successful',
            'data': {
                'access_token': 'test_token',
                'refresh_token': 'test_refresh_token',
                'token_type': 'Bearer',
                'expires_in': 86400
            }
        }
        mock_post.return_value = mock_login_response
        
        # Mock task creation response
        mock_task_response = MagicMock()
        mock_task_response.status_code = 201
        mock_task_response.json.return_value = {
            'status': 'success',
            'message': 'Task created successfully',
            'data': {
                'task': {
                    'id': 'test_task_id',
                    'name': 'Test Vulnerability Scan',
                    'status': 'scheduled'
                }
            }
        }
        mock_post.return_value = mock_task_response
        
        # Mock task status response
        mock_status_response = MagicMock()
        mock_status_response.status_code = 200
        mock_status_response.json.return_value = {
            'status': 'success',
            'message': 'Task statuses retrieved successfully',
            'data': {
                'tasks': [
                    {
                        'id': 'test_task_id',
                        'status': 'completed',
                        'progress': 100,
                        'updated_at': '2025-05-10T10:00:00Z'
                    }
                ]
            }
        }
        mock_post.return_value = mock_status_response
        
        # Mock task result response
        mock_result_response = MagicMock()
        mock_result_response.status_code = 200
        mock_result_response.json.return_value = {
            'status': 'success',
            'message': 'Task retrieved successfully',
            'data': {
                'task': {
                    'id': 'test_task_id',
                    'name': 'Test Vulnerability Scan',
                    'status': 'completed',
                    'result': {
                        'vulnerabilities': 2,
                        'details': [
                            {'id': 'CVE-2021-44228', 'severity': 'critical'},
                            {'id': 'CVE-2021-3449', 'severity': 'medium'}
                        ]
                    }
                }
            }
        }
        mock_get.return_value = mock_result_response
        
        # Step 1: Login to API
        login_data = {
            'username': 'test_user',
            'password': 'test_password'
        }
        login_response = requests.post('http://localhost:5000/api/auth/login', json=login_data)
        self.assertEqual(login_response.status_code, 200)
        
        # Extract token
        token = login_response.json()['data']['access_token']
        self.assertEqual(token, 'test_token')
        
        # Step 2: Create a vulnerability scan task
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        task_data = {
            'name': 'Test Vulnerability Scan',
            'module': 'vulnerability.scanner',
            'target': self.test_domain,
            'options': {
                'intensity': 'high'
            }
        }
        task_response = requests.post('http://localhost:5000/api/tasks', json=task_data, headers=headers)
        self.assertEqual(task_response.status_code, 201)
        
        # Extract task ID
        task_id = task_response.json()['data']['task']['id']
        self.assertEqual(task_id, 'test_task_id')
        
        # Step 3: Check task status
        status_data = {
            'task_ids': [task_id]
        }
        status_response = requests.post('http://localhost:5000/api/tasks/status', json=status_data, headers=headers)
        self.assertEqual(status_response.status_code, 200)
        
        # Verify task is completed
        task_status = status_response.json()['data']['tasks'][0]['status']
        self.assertEqual(task_status, 'completed')
        
        # Step 4: Get task results
        result_response = requests.get(f'http://localhost:5000/api/tasks/{task_id}', headers=headers)
        self.assertEqual(result_response.status_code, 200)
        
        # Verify task results
        task_result = result_response.json()['data']['task']['result']
        self.assertEqual(task_result['vulnerabilities'], 2)
        self.assertEqual(task_result['details'][0]['id'], 'CVE-2021-44228')

    @patch('orchestrator.cli.click.echo')
    @patch('modules.security.port_scanner.scan_ports')
    def test_cli_workflow(self, mock_port_scan, mock_echo):
        """Test the CLI workflow for security scanning"""
        # Mock port scan results
        mock_port_scan.return_value = {
            80: True,
            443: True,
            22: True,
            3306: False
        }
        
        # Create a runner for the CLI app
        from click.testing import CliRunner
        runner = CliRunner()
        
        # Run the port scan command
        result = runner.invoke(cli_app, ['security', 'portscan', self.test_ip, '--ports', '22,80,443,3306'])
        
        # Verify the command executed successfully
        self.assertEqual(result.exit_code, 0)
        
        # Verify port_scanner.scan_ports was called with correct arguments
        mock_port_scan.assert_called_once()
        args, kwargs = mock_port_scan.call_args
        self.assertEqual(args[0], self.test_ip)
        self.assertEqual(sorted(args[1]), [22, 80, 443, 3306])
        
        # Verify output was displayed
        mock_echo.assert_any_call(f"Port Scan Results for {self.test_ip}:")
        mock_echo.assert_any_call("Port 80: Open")
        mock_echo.assert_any_call("Port 443: Open")
        mock_echo.assert_any_call("Port 22: Open")
        mock_echo.assert_any_call("Port 3306: Closed")


if __name__ == '__main__':
    unittest.main()
