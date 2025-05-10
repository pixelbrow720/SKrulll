"""
Unit tests for the Entry Point Analyzer module.

This module contains tests for the EntryPointAnalyzer class, which is responsible
for identifying and analyzing potential entry points in a target system.
"""
import unittest
from unittest.mock import patch, MagicMock
import json
import os
import sys

# Add project root to path
sys.path.append('.')

from modules.security.entry_point_analyzer import EntryPointAnalyzer


class TestEntryPointAnalyzer(unittest.TestCase):
    """Test cases for the EntryPointAnalyzer class"""

    def setUp(self):
        """Set up test fixtures"""
        self.target_url = "https://example.com"
        self.config = {
            "scan_depth": 2,
            "timeout": 10,
            "user_agent": "SKrulll Security Scanner/1.0",
            "follow_redirects": True,
            "max_urls": 100,
            "exclude_patterns": [
                "logout",
                "delete",
                "admin"
            ]
        }
        self.analyzer = EntryPointAnalyzer(self.target_url, self.config)
        
        # Sample data for tests
        self.sample_endpoints = [
            {"url": "https://example.com/api/users", "method": "GET", "params": []},
            {"url": "https://example.com/api/users", "method": "POST", "params": ["name", "email"]},
            {"url": "https://example.com/api/products", "method": "GET", "params": ["category", "sort"]},
            {"url": "https://example.com/api/login", "method": "POST", "params": ["username", "password"]}
        ]
        
        self.sample_headers = {
            "Server": "nginx/1.18.0",
            "Content-Type": "application/json",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains"
        }
        
        self.sample_technologies = [
            {"name": "nginx", "version": "1.18.0", "category": "web-server"},
            {"name": "React", "version": "17.0.2", "category": "javascript-framework"},
            {"name": "PHP", "version": "7.4.3", "category": "programming-language"},
            {"name": "MySQL", "version": "8.0.23", "category": "database"}
        ]

    @patch('modules.security.entry_point_analyzer.requests.get')
    def test_analyze_headers(self, mock_get):
        """Test analyzing HTTP headers"""
        # Mock the response
        mock_response = MagicMock()
        mock_response.headers = self.sample_headers
        mock_get.return_value = mock_response
        
        # Call the method
        headers_analysis = self.analyzer.analyze_headers()
        
        # Verify the results
        self.assertIsInstance(headers_analysis, dict)
        self.assertIn("headers", headers_analysis)
        self.assertIn("security_headers", headers_analysis)
        self.assertIn("missing_security_headers", headers_analysis)
        
        # Check that the headers were correctly analyzed
        self.assertEqual(headers_analysis["headers"], self.sample_headers)
        self.assertIn("X-Frame-Options", headers_analysis["security_headers"])
        self.assertIn("X-Content-Type-Options", headers_analysis["security_headers"])
        self.assertIn("Strict-Transport-Security", headers_analysis["security_headers"])
        
        # Verify that the method was called with the correct parameters
        mock_get.assert_called_once_with(
            self.target_url,
            headers={"User-Agent": self.config["user_agent"]},
            timeout=self.config["timeout"],
            allow_redirects=self.config["follow_redirects"],
            verify=True
        )

    @patch('modules.security.entry_point_analyzer.requests.get')
    def test_analyze_headers_missing_security_headers(self, mock_get):
        """Test analyzing HTTP headers with missing security headers"""
        # Mock the response with minimal headers
        mock_response = MagicMock()
        mock_response.headers = {
            "Server": "nginx/1.18.0",
            "Content-Type": "application/json"
        }
        mock_get.return_value = mock_response
        
        # Call the method
        headers_analysis = self.analyzer.analyze_headers()
        
        # Verify the results
        self.assertIsInstance(headers_analysis, dict)
        self.assertIn("missing_security_headers", headers_analysis)
        
        # Check that missing security headers were correctly identified
        missing_headers = headers_analysis["missing_security_headers"]
        self.assertIn("X-Frame-Options", missing_headers)
        self.assertIn("X-Content-Type-Options", missing_headers)
        self.assertIn("Strict-Transport-Security", missing_headers)
        self.assertIn("Content-Security-Policy", missing_headers)

    @patch('modules.security.entry_point_analyzer.EntryPointAnalyzer._discover_endpoints')
    def test_analyze_endpoints(self, mock_discover):
        """Test analyzing endpoints"""
        # Mock the endpoint discovery
        mock_discover.return_value = self.sample_endpoints
        
        # Call the method
        endpoints_analysis = self.analyzer.analyze_endpoints()
        
        # Verify the results
        self.assertIsInstance(endpoints_analysis, dict)
        self.assertIn("total_endpoints", endpoints_analysis)
        self.assertIn("methods", endpoints_analysis)
        self.assertIn("parameters", endpoints_analysis)
        self.assertIn("authentication_endpoints", endpoints_analysis)
        
        # Check that the endpoints were correctly analyzed
        self.assertEqual(endpoints_analysis["total_endpoints"], 4)
        self.assertEqual(endpoints_analysis["methods"]["GET"], 2)
        self.assertEqual(endpoints_analysis["methods"]["POST"], 2)
        
        # Check that parameters were correctly analyzed
        self.assertIn("username", endpoints_analysis["parameters"])
        self.assertIn("password", endpoints_analysis["parameters"])
        
        # Check that authentication endpoints were correctly identified
        self.assertEqual(len(endpoints_analysis["authentication_endpoints"]), 1)
        self.assertEqual(endpoints_analysis["authentication_endpoints"][0]["url"], "https://example.com/api/login")

    @patch('modules.security.entry_point_analyzer.EntryPointAnalyzer._detect_technologies')
    def test_analyze_technologies(self, mock_detect):
        """Test analyzing technologies"""
        # Mock the technology detection
        mock_detect.return_value = self.sample_technologies
        
        # Call the method
        tech_analysis = self.analyzer.analyze_technologies()
        
        # Verify the results
        self.assertIsInstance(tech_analysis, dict)
        self.assertIn("technologies", tech_analysis)
        self.assertIn("categories", tech_analysis)
        self.assertIn("versions", tech_analysis)
        
        # Check that the technologies were correctly analyzed
        self.assertEqual(len(tech_analysis["technologies"]), 4)
        self.assertEqual(tech_analysis["categories"]["web-server"], 1)
        self.assertEqual(tech_analysis["categories"]["javascript-framework"], 1)
        
        # Check that versions were correctly analyzed
        self.assertEqual(tech_analysis["versions"]["nginx"], "1.18.0")
        self.assertEqual(tech_analysis["versions"]["React"], "17.0.2")

    def test_generate_access_matrix(self):
        """Test generating an access matrix"""
        # Mock the endpoint data
        self.analyzer.endpoints = [
            {"url": "https://example.com/api/users", "method": "GET", "params": [], "auth_required": False},
            {"url": "https://example.com/api/users", "method": "POST", "params": ["name", "email"], "auth_required": True},
            {"url": "https://example.com/api/products", "method": "GET", "params": ["category", "sort"], "auth_required": False},
            {"url": "https://example.com/api/admin", "method": "GET", "params": [], "auth_required": True}
        ]
        
        # Define roles
        roles = ["anonymous", "user", "admin"]
        
        # Call the method
        access_matrix = self.analyzer.generate_access_matrix(roles)
        
        # Verify the results
        self.assertIsInstance(access_matrix, dict)
        self.assertIn("matrix", access_matrix)
        self.assertIn("roles", access_matrix)
        self.assertIn("endpoints", access_matrix)
        
        # Check that the matrix was correctly generated
        matrix = access_matrix["matrix"]
        self.assertEqual(len(matrix), len(roles))
        self.assertEqual(len(matrix[0]), len(self.analyzer.endpoints))
        
        # Anonymous users should have access to non-auth endpoints
        self.assertTrue(matrix[0][0])  # anonymous -> GET /api/users
        self.assertFalse(matrix[0][1])  # anonymous -> POST /api/users (auth required)
        self.assertTrue(matrix[0][2])  # anonymous -> GET /api/products
        self.assertFalse(matrix[0][3])  # anonymous -> GET /api/admin (auth required)
        
        # Admin users should have access to all endpoints
        self.assertTrue(matrix[2][0])  # admin -> GET /api/users
        self.assertTrue(matrix[2][1])  # admin -> POST /api/users
        self.assertTrue(matrix[2][2])  # admin -> GET /api/products
        self.assertTrue(matrix[2][3])  # admin -> GET /api/admin

    def test_calculate_risk_scores(self):
        """Test calculating risk scores for entry points"""
        # Mock the endpoint data
        self.analyzer.endpoints = [
            {
                "url": "https://example.com/api/login", 
                "method": "POST", 
                "params": ["username", "password"],
                "auth_required": False
            },
            {
                "url": "https://example.com/api/users", 
                "method": "GET", 
                "params": [],
                "auth_required": True
            },
            {
                "url": "https://example.com/api/admin/users", 
                "method": "DELETE", 
                "params": ["id"],
                "auth_required": True
            }
        ]
        
        # Call the method
        risk_scores = self.analyzer.calculate_risk_scores()
        
        # Verify the results
        self.assertIsInstance(risk_scores, dict)
        self.assertIn("endpoint_risks", risk_scores)
        self.assertIn("high_risk_endpoints", risk_scores)
        self.assertIn("average_risk", risk_scores)
        
        # Check that the risk scores were correctly calculated
        endpoint_risks = risk_scores["endpoint_risks"]
        self.assertEqual(len(endpoint_risks), 3)
        
        # Login endpoints should have high risk
        login_risk = next(r for r in endpoint_risks if r["url"] == "https://example.com/api/login")
        self.assertGreater(login_risk["risk_score"], 0.7)
        
        # Admin endpoints should have high risk
        admin_risk = next(r for r in endpoint_risks if r["url"] == "https://example.com/api/admin/users")
        self.assertGreater(admin_risk["risk_score"], 0.7)
        
        # Regular GET endpoints should have lower risk
        users_risk = next(r for r in endpoint_risks if r["url"] == "https://example.com/api/users")
        self.assertLess(users_risk["risk_score"], 0.5)
        
        # Check high risk endpoints
        self.assertGreaterEqual(len(risk_scores["high_risk_endpoints"]), 1)
        
        # Check average risk
        self.assertGreater(risk_scores["average_risk"], 0)
        self.assertLess(risk_scores["average_risk"], 1)

    def test_generate_report(self):
        """Test generating a comprehensive report"""
        # Mock the analysis results
        headers_analysis = {
            "headers": self.sample_headers,
            "security_headers": ["X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security"],
            "missing_security_headers": ["Content-Security-Policy"]
        }
        
        endpoints_analysis = {
            "total_endpoints": 4,
            "methods": {"GET": 2, "POST": 2},
            "parameters": ["username", "password", "name", "email", "category", "sort"],
            "authentication_endpoints": [{"url": "https://example.com/api/login", "method": "POST"}]
        }
        
        tech_analysis = {
            "technologies": self.sample_technologies,
            "categories": {"web-server": 1, "javascript-framework": 1, "programming-language": 1, "database": 1},
            "versions": {"nginx": "1.18.0", "React": "17.0.2", "PHP": "7.4.3", "MySQL": "8.0.23"}
        }
        
        risk_scores = {
            "endpoint_risks": [
                {"url": "https://example.com/api/login", "risk_score": 0.8},
                {"url": "https://example.com/api/users", "risk_score": 0.4}
            ],
            "high_risk_endpoints": [
                {"url": "https://example.com/api/login", "risk_score": 0.8}
            ],
            "average_risk": 0.6
        }
        
        # Mock the analyzer's methods
        self.analyzer.analyze_headers = MagicMock(return_value=headers_analysis)
        self.analyzer.analyze_endpoints = MagicMock(return_value=endpoints_analysis)
        self.analyzer.analyze_technologies = MagicMock(return_value=tech_analysis)
        self.analyzer.calculate_risk_scores = MagicMock(return_value=risk_scores)
        
        # Call the method
        report = self.analyzer.generate_report()
        
        # Verify the results
        self.assertIsInstance(report, dict)
        self.assertIn("target", report)
        self.assertIn("scan_date", report)
        self.assertIn("headers_analysis", report)
        self.assertIn("endpoints_analysis", report)
        self.assertIn("technologies_analysis", report)
        self.assertIn("risk_assessment", report)
        self.assertIn("recommendations", report)
        
        # Check that the report contains the correct data
        self.assertEqual(report["target"], self.target_url)
        self.assertEqual(report["headers_analysis"], headers_analysis)
        self.assertEqual(report["endpoints_analysis"], endpoints_analysis)
        self.assertEqual(report["technologies_analysis"], tech_analysis)
        self.assertEqual(report["risk_assessment"], risk_scores)
        
        # Check that recommendations were generated
        self.assertGreater(len(report["recommendations"]), 0)

    def test_export_report(self):
        """Test exporting the report to a file"""
        # Create a temporary file path
        temp_file = "test_report.json"
        
        # Mock the report
        report = {
            "target": self.target_url,
            "scan_date": "2025-05-10T10:00:00Z",
            "headers_analysis": {"headers": self.sample_headers},
            "endpoints_analysis": {"total_endpoints": 4},
            "technologies_analysis": {"technologies": self.sample_technologies},
            "risk_assessment": {"average_risk": 0.6},
            "recommendations": ["Implement Content-Security-Policy header"]
        }
        
        # Mock the generate_report method
        self.analyzer.generate_report = MagicMock(return_value=report)
        
        try:
            # Call the method
            file_path = self.analyzer.export_report(temp_file)
            
            # Verify the results
            self.assertEqual(file_path, temp_file)
            self.assertTrue(os.path.exists(temp_file))
            
            # Check that the file contains the correct data
            with open(temp_file, 'r') as f:
                saved_report = json.load(f)
            
            self.assertEqual(saved_report, report)
            
        finally:
            # Clean up
            if os.path.exists(temp_file):
                os.remove(temp_file)


if __name__ == '__main__':
    unittest.main()
