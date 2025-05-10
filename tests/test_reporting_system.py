"""
Unit tests for the Reporting System module.

This module contains tests for the ReportingSystem class, which is responsible
for generating reports from security assessment data.
"""
import unittest
from unittest.mock import patch, MagicMock, mock_open
import json
import os
import sys
import tempfile
from datetime import datetime

# Add project root to path
sys.path.append('.')

from modules.security.reporting_system import ReportingSystem


class TestReportingSystem(unittest.TestCase):
    """Test cases for the ReportingSystem class"""

    def setUp(self):
        """Set up test fixtures"""
        self.config = {
            'output_dir': '/tmp/skrulll_reports',
            'company_name': 'Test Company',
            'logo_path': 'static/img/logo.png',
            'report_templates': {
                'pdf': 'templates/reports/pdf_report.html',
                'html': 'templates/reports/html_report.html',
                'json': None  # JSON doesn't need a template
            }
        }
        
        # Create the reporting system
        self.reporting = ReportingSystem(self.config)
        
        # Sample data for tests
        self.vulnerability_data = {
            'vulnerabilities': [
                {
                    'host': '192.168.1.1',
                    'id': 'CVE-2021-44228',
                    'name': 'Log4j RCE',
                    'severity': 'critical',
                    'cvss': 10.0,
                    'description': 'Remote code execution vulnerability in Log4j',
                    'recommendation': 'Update to Log4j 2.15.0 or later'
                },
                {
                    'host': '192.168.1.2',
                    'id': 'CVE-2021-3449',
                    'name': 'OpenSSL DoS',
                    'severity': 'medium',
                    'cvss': 5.9,
                    'description': 'Denial of service vulnerability in OpenSSL',
                    'recommendation': 'Update to OpenSSL 1.1.1k or later'
                }
            ],
            'scan_date': '2025-05-10T10:00:00Z',
            'target': 'example.com'
        }
        
        self.network_data = {
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
            ],
            'attack_paths': [
                {
                    'source': '192.168.1.1',
                    'target': '192.168.1.2',
                    'risk_score': 0.9,
                    'description': 'Attacker can exploit Log4j RCE on web-server to gain access to db-server',
                    'recommendations': [
                        'Update Log4j on web-server',
                        'Implement network segmentation between web and database servers'
                    ]
                }
            ]
        }

    @patch('os.makedirs')
    def test_init(self, mock_makedirs):
        """Test initialization of the ReportingSystem"""
        # Verify that the output directory is created
        mock_makedirs.assert_called_once_with(self.config['output_dir'], exist_ok=True)
        
        # Verify that the configuration is stored
        self.assertEqual(self.reporting.config, self.config)
        self.assertEqual(self.reporting.output_dir, self.config['output_dir'])
        self.assertEqual(self.reporting.company_name, self.config['company_name'])
        self.assertEqual(self.reporting.logo_path, self.config['logo_path'])

    def test_process_findings(self):
        """Test processing vulnerability findings"""
        # Call the method
        processed_data = self.reporting._process_findings(self.vulnerability_data)
        
        # Verify the processed data
        self.assertIsInstance(processed_data, dict)
        self.assertIn('summary', processed_data)
        self.assertIn('vulnerabilities_by_severity', processed_data)
        self.assertIn('vulnerabilities_by_host', processed_data)
        
        # Check the summary
        summary = processed_data['summary']
        self.assertEqual(summary['total_vulnerabilities'], 2)
        self.assertEqual(summary['critical_count'], 1)
        self.assertEqual(summary['high_count'], 0)
        self.assertEqual(summary['medium_count'], 1)
        self.assertEqual(summary['low_count'], 0)
        
        # Check vulnerabilities by severity
        by_severity = processed_data['vulnerabilities_by_severity']
        self.assertEqual(len(by_severity['critical']), 1)
        self.assertEqual(len(by_severity['medium']), 1)
        self.assertEqual(by_severity['critical'][0]['name'], 'Log4j RCE')
        self.assertEqual(by_severity['medium'][0]['name'], 'OpenSSL DoS')
        
        # Check vulnerabilities by host
        by_host = processed_data['vulnerabilities_by_host']
        self.assertEqual(len(by_host['192.168.1.1']), 1)
        self.assertEqual(len(by_host['192.168.1.2']), 1)
        self.assertEqual(by_host['192.168.1.1'][0]['name'], 'Log4j RCE')
        self.assertEqual(by_host['192.168.1.2'][0]['name'], 'OpenSSL DoS')

    def test_process_network_data(self):
        """Test processing network data"""
        # Call the method
        processed_data = self.reporting._process_network_data(self.network_data)
        
        # Verify the processed data
        self.assertIsInstance(processed_data, dict)
        self.assertIn('summary', processed_data)
        self.assertIn('hosts', processed_data)
        self.assertIn('attack_paths', processed_data)
        
        # Check the summary
        summary = processed_data['summary']
        self.assertEqual(summary['total_hosts'], 2)
        self.assertEqual(summary['total_open_ports'], 5)
        self.assertEqual(summary['total_attack_paths'], 1)
        
        # Check hosts
        hosts = processed_data['hosts']
        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts[0]['ip'], '192.168.1.1')
        self.assertEqual(hosts[0]['hostname'], 'web-server')
        self.assertEqual(len(hosts[0]['ports']), 3)
        
        # Check attack paths
        attack_paths = processed_data['attack_paths']
        self.assertEqual(len(attack_paths), 1)
        self.assertEqual(attack_paths[0]['source'], '192.168.1.1')
        self.assertEqual(attack_paths[0]['target'], '192.168.1.2')
        self.assertEqual(attack_paths[0]['risk_score'], 0.9)

    def test_generate_executive_summary(self):
        """Test generating an executive summary"""
        # Prepare processed data
        processed_findings = {
            'summary': {
                'total_vulnerabilities': 2,
                'critical_count': 1,
                'high_count': 0,
                'medium_count': 1,
                'low_count': 0
            }
        }
        
        processed_network = {
            'summary': {
                'total_hosts': 2,
                'total_open_ports': 5,
                'total_attack_paths': 1
            },
            'attack_paths': [
                {
                    'source': '192.168.1.1',
                    'target': '192.168.1.2',
                    'risk_score': 0.9,
                    'description': 'Attacker can exploit Log4j RCE on web-server to gain access to db-server'
                }
            ]
        }
        
        # Call the method
        summary = self.reporting._generate_executive_summary(
            'example.com',
            processed_findings,
            processed_network
        )
        
        # Verify the summary
        self.assertIsInstance(summary, dict)
        self.assertIn('target', summary)
        self.assertIn('scan_date', summary)
        self.assertIn('risk_level', summary)
        self.assertIn('key_findings', summary)
        self.assertIn('recommendations', summary)
        
        # Check the content
        self.assertEqual(summary['target'], 'example.com')
        self.assertIsInstance(summary['scan_date'], str)
        self.assertEqual(summary['risk_level'], 'Critical')  # Due to critical vulnerability
        self.assertGreater(len(summary['key_findings']), 0)
        self.assertGreater(len(summary['recommendations']), 0)

    @patch('modules.security.reporting_system.ReportingSystem._generate_pdf_report')
    def test_generate_report_pdf(self, mock_pdf):
        """Test generating a PDF report"""
        # Set up the mock
        mock_pdf.return_value = '/tmp/skrulll_reports/report.pdf'
        
        # Call the method
        report_file = self.reporting.generate_report(
            {
                'vulnerabilities': self.vulnerability_data['vulnerabilities'],
                'network_map': self.network_data,
                'target': 'example.com'
            },
            'pdf'
        )
        
        # Verify that the PDF generator was called
        mock_pdf.assert_called_once()
        
        # Verify the returned file path
        self.assertEqual(report_file, '/tmp/skrulll_reports/report.pdf')

    @patch('modules.security.reporting_system.ReportingSystem._generate_html_report')
    def test_generate_report_html(self, mock_html):
        """Test generating an HTML report"""
        # Set up the mock
        mock_html.return_value = '/tmp/skrulll_reports/report.html'
        
        # Call the method
        report_file = self.reporting.generate_report(
            {
                'vulnerabilities': self.vulnerability_data['vulnerabilities'],
                'network_map': self.network_data,
                'target': 'example.com'
            },
            'html'
        )
        
        # Verify that the HTML generator was called
        mock_html.assert_called_once()
        
        # Verify the returned file path
        self.assertEqual(report_file, '/tmp/skrulll_reports/report.html')

    @patch('builtins.open', new_callable=mock_open)
    def test_generate_report_json(self, mock_file):
        """Test generating a JSON report"""
        # Call the method
        report_file = self.reporting.generate_report(
            {
                'vulnerabilities': self.vulnerability_data['vulnerabilities'],
                'network_map': self.network_data,
                'target': 'example.com'
            },
            'json'
        )
        
        # Verify that the file was opened for writing
        mock_file.assert_called_once()
        
        # Verify that the JSON data was written
        mock_file().write.assert_called_once()
        write_arg = mock_file().write.call_args[0][0]
        self.assertIsInstance(write_arg, str)
        
        # Verify that the written data is valid JSON
        try:
            json_data = json.loads(write_arg)
            self.assertIsInstance(json_data, dict)
            self.assertIn('executive_summary', json_data)
            self.assertIn('vulnerabilities', json_data)
            self.assertIn('network', json_data)
        except json.JSONDecodeError:
            self.fail("Written data is not valid JSON")
        
        # Verify the returned file path
        self.assertTrue(report_file.endswith('.json'))

    def test_generate_report_invalid_format(self):
        """Test generating a report with an invalid format"""
        # Call the method with an invalid format
        with self.assertRaises(ValueError):
            self.reporting.generate_report(
                {
                    'vulnerabilities': self.vulnerability_data['vulnerabilities'],
                    'network_map': self.network_data,
                    'target': 'example.com'
                },
                'invalid_format'
            )

    @patch('modules.security.reporting_system.jinja2.Environment')
    @patch('modules.security.reporting_system.weasyprint.HTML')
    @patch('builtins.open', new_callable=mock_open)
    def test_generate_pdf_report(self, mock_file, mock_weasyprint, mock_jinja):
        """Test generating a PDF report"""
        # Set up mocks
        mock_template = MagicMock()
        mock_jinja.return_value.get_template.return_value = mock_template
        mock_template.render.return_value = '<html><body>Test Report</body></html>'
        
        mock_html = MagicMock()
        mock_weasyprint.return_value = mock_html
        
        # Call the method
        report_data = {
            'executive_summary': {'target': 'example.com'},
            'vulnerabilities': {'summary': {'total_vulnerabilities': 2}},
            'network': {'summary': {'total_hosts': 2}}
        }
        
        report_file = self.reporting._generate_pdf_report(report_data)
        
        # Verify that the template was rendered
        mock_jinja.return_value.get_template.assert_called_once()
        mock_template.render.assert_called_once_with(report=report_data)
        
        # Verify that WeasyPrint was called
        mock_weasyprint.assert_called_once()
        mock_html.write_pdf.assert_called_once()
        
        # Verify the returned file path
        self.assertTrue(report_file.endswith('.pdf'))

    @patch('modules.security.reporting_system.jinja2.Environment')
    @patch('builtins.open', new_callable=mock_open)
    def test_generate_html_report(self, mock_file, mock_jinja):
        """Test generating an HTML report"""
        # Set up mocks
        mock_template = MagicMock()
        mock_jinja.return_value.get_template.return_value = mock_template
        mock_template.render.return_value = '<html><body>Test Report</body></html>'
        
        # Call the method
        report_data = {
            'executive_summary': {'target': 'example.com'},
            'vulnerabilities': {'summary': {'total_vulnerabilities': 2}},
            'network': {'summary': {'total_hosts': 2}}
        }
        
        report_file = self.reporting._generate_html_report(report_data)
        
        # Verify that the template was rendered
        mock_jinja.return_value.get_template.assert_called_once()
        mock_template.render.assert_called_once_with(report=report_data)
        
        # Verify that the file was written
        mock_file.assert_called_once()
        mock_file().write.assert_called_once_with('<html><body>Test Report</body></html>')
        
        # Verify the returned file path
        self.assertTrue(report_file.endswith('.html'))

    def test_generate_filename(self):
        """Test generating a filename for a report"""
        # Call the method
        filename = self.reporting._generate_filename('example.com', 'pdf')
        
        # Verify the filename format
        self.assertTrue(filename.startswith('security_report_example.com_'))
        self.assertTrue(filename.endswith('.pdf'))
        
        # Extract the date part
        date_part = filename.split('_')[3].split('.')[0]
        
        # Verify that the date part is a valid date
        try:
            datetime.strptime(date_part, '%Y%m%d')
        except ValueError:
            self.fail("Date part of filename is not a valid date")

    def test_calculate_risk_level(self):
        """Test calculating the overall risk level"""
        # Test with critical vulnerabilities
        risk_level = self.reporting._calculate_risk_level({'critical_count': 1, 'high_count': 0, 'medium_count': 0, 'low_count': 0})
        self.assertEqual(risk_level, 'Critical')
        
        # Test with high vulnerabilities
        risk_level = self.reporting._calculate_risk_level({'critical_count': 0, 'high_count': 1, 'medium_count': 0, 'low_count': 0})
        self.assertEqual(risk_level, 'High')
        
        # Test with medium vulnerabilities
        risk_level = self.reporting._calculate_risk_level({'critical_count': 0, 'high_count': 0, 'medium_count': 1, 'low_count': 0})
        self.assertEqual(risk_level, 'Medium')
        
        # Test with low vulnerabilities
        risk_level = self.reporting._calculate_risk_level({'critical_count': 0, 'high_count': 0, 'medium_count': 0, 'low_count': 1})
        self.assertEqual(risk_level, 'Low')
        
        # Test with no vulnerabilities
        risk_level = self.reporting._calculate_risk_level({'critical_count': 0, 'high_count': 0, 'medium_count': 0, 'low_count': 0})
        self.assertEqual(risk_level, 'Informational')

    def test_generate_key_findings(self):
        """Test generating key findings"""
        # Prepare data
        vuln_summary = {
            'total_vulnerabilities': 2,
            'critical_count': 1,
            'high_count': 0,
            'medium_count': 1,
            'low_count': 0
        }
        
        network_summary = {
            'total_hosts': 2,
            'total_open_ports': 5,
            'total_attack_paths': 1
        }
        
        # Call the method
        findings = self.reporting._generate_key_findings(vuln_summary, network_summary)
        
        # Verify the findings
        self.assertIsInstance(findings, list)
        self.assertGreater(len(findings), 0)
        
        # Check that the findings mention the critical vulnerability
        self.assertTrue(any('critical' in finding.lower() for finding in findings))
        
        # Check that the findings mention the attack path
        self.assertTrue(any('attack path' in finding.lower() for finding in findings))

    def test_generate_recommendations(self):
        """Test generating recommendations"""
        # Prepare data
        vulnerabilities = [
            {
                'name': 'Log4j RCE',
                'severity': 'critical',
                'recommendation': 'Update to Log4j 2.15.0 or later'
            },
            {
                'name': 'OpenSSL DoS',
                'severity': 'medium',
                'recommendation': 'Update to OpenSSL 1.1.1k or later'
            }
        ]
        
        attack_paths = [
            {
                'recommendations': [
                    'Implement network segmentation between web and database servers'
                ]
            }
        ]
        
        # Call the method
        recommendations = self.reporting._generate_recommendations(vulnerabilities, attack_paths)
        
        # Verify the recommendations
        self.assertIsInstance(recommendations, list)
        self.assertGreater(len(recommendations), 0)
        
        # Check that the recommendations include the vulnerability recommendations
        self.assertTrue(any('Log4j' in rec for rec in recommendations))
        self.assertTrue(any('OpenSSL' in rec for rec in recommendations))
        
        # Check that the recommendations include the attack path recommendations
        self.assertTrue(any('network segmentation' in rec for rec in recommendations))


if __name__ == '__main__':
    unittest.main()
