
"""
Integrated Reporting System - Generates comprehensive security reports
"""
import logging
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
import jinja2
import pdfkit
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class SecurityFinding:
    title: str
    severity: str
    description: str
    impact: str
    recommendation: str
    cvss_score: float

class ReportingSystem:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.template_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader('templates/reports')
        )
    
    def generate_report(self, data: Dict[str, Any], output_format: str = 'pdf') -> str:
        """Generate security report in specified format"""
        # Process and organize data
        findings = self._process_findings(data)
        risk_summary = self._calculate_risk_summary(findings)
        
        # Create report context
        context = {
            'title': 'Security Assessment Report',
            'date': datetime.now().strftime('%Y-%m-%d'),
            'findings': findings,
            'risk_summary': risk_summary,
            'executive_summary': self._generate_executive_summary(findings, risk_summary)
        }
        
        # Generate report in requested format
        if output_format == 'pdf':
            return self._generate_pdf_report(context)
        else:
            return self._generate_html_report(context)
    
    def _process_findings(self, data: Dict[str, Any]) -> List[SecurityFinding]:
        """Process raw findings data into structured format"""
        findings = []
        
        # Process vulnerability scan results
        for vuln in data.get('vulnerabilities', []):
            finding = SecurityFinding(
                title=vuln['name'],
                severity=vuln['severity'],
                description=vuln.get('description', ''),
                impact=vuln.get('impact', ''),
                recommendation=vuln.get('recommendation', ''),
                cvss_score=float(vuln.get('cvss_score', 0.0))
            )
            findings.append(finding)
        
        # Process network mapping results
        for host in data.get('network_map', {}).get('hosts', []):
            for issue in host.get('issues', []):
                finding = SecurityFinding(
                    title=f"Network Issue: {issue['type']}",
                    severity=issue['severity'],
                    description=issue.get('description', ''),
                    impact=issue.get('impact', ''),
                    recommendation=issue.get('recommendation', ''),
                    cvss_score=float(issue.get('cvss_score', 0.0))
                )
                findings.append(finding)
        
        # Process API security results
        for endpoint in data.get('api_security', {}).get('endpoints', []):
            if endpoint.get('issues'):
                finding = SecurityFinding(
                    title=f"API Security Issue: {endpoint['path']}",
                    severity=self._calculate_api_severity(endpoint),
                    description=endpoint.get('description', ''),
                    impact=endpoint.get('impact', ''),
                    recommendation=endpoint.get('recommendation', ''),
                    cvss_score=float(endpoint.get('risk_score', 0.0))
                )
                findings.append(finding)
        
        return findings
    
    def _calculate_risk_summary(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Calculate risk metrics and summary"""
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        total_cvss = 0.0
        
        for finding in findings:
            severity_counts[finding.severity.lower()] += 1
            total_cvss += finding.cvss_score
        
        avg_cvss = total_cvss / len(findings) if findings else 0.0
        
        return {
            'total_findings': len(findings),
            'severity_counts': severity_counts,
            'average_cvss': avg_cvss,
            'risk_level': self._determine_risk_level(severity_counts, avg_cvss)
        }
    
    def _generate_executive_summary(self, findings: List[SecurityFinding],
                                  risk_summary: Dict[str, Any]) -> str:
        """Generate executive summary of findings"""
        critical_high = risk_summary['severity_counts']['critical'] + risk_summary['severity_counts']['high']
        
        summary = f"""
Security assessment identified {risk_summary['total_findings']} findings, including {critical_high} critical/high risk issues.
Overall risk level is assessed as {risk_summary['risk_level'].upper()}.
The average CVSS score across all findings is {risk_summary['average_cvss']:.1f}.

Key Findings:
"""
        
        # Add top 3 critical/high findings
        critical_findings = [f for f in findings if f.severity.lower() in ['critical', 'high']]
        for i, finding in enumerate(sorted(critical_findings, key=lambda x: x.cvss_score, reverse=True)[:3], 1):
            summary += f"\n{i}. {finding.title} (CVSS: {finding.cvss_score:.1f})"
        
        return summary
    
    def _generate_pdf_report(self, context: Dict[str, Any]) -> str:
        """Generate PDF report"""
        template = self.template_env.get_template('report.html')
        html_content = template.render(**context)
        
        output_file = f"reports/security_report_{datetime.now().strftime('%Y%m%d')}.pdf"
        
        # Convert HTML to PDF
        pdfkit.from_string(
            html_content,
            output_file,
            options={
                'page-size': 'A4',
                'margin-top': '20mm',
                'margin-right': '20mm',
                'margin-bottom': '20mm',
                'margin-left': '20mm'
            }
        )
        
        return output_file
    
    def _generate_html_report(self, context: Dict[str, Any]) -> str:
        """Generate HTML report"""
        template = self.template_env.get_template('report.html')
        html_content = template.render(**context)
        
        output_file = f"reports/security_report_{datetime.now().strftime('%Y%m%d')}.html"
        
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        return output_file
    
    def _calculate_api_severity(self, endpoint: Dict[str, Any]) -> str:
        """Calculate severity for API endpoint issues"""
        risk_score = float(endpoint.get('risk_score', 0.0))
        
        if risk_score >= 2.5:
            return 'critical'
        elif risk_score >= 2.0:
            return 'high'
        elif risk_score >= 1.5:
            return 'medium'
        return 'low'
    
    def _determine_risk_level(self, severity_counts: Dict[str, int],
                            avg_cvss: float) -> str:
        """Determine overall risk level"""
        if severity_counts['critical'] > 0 or avg_cvss >= 9.0:
            return 'critical'
        elif severity_counts['high'] > 2 or avg_cvss >= 7.0:
            return 'high'
        elif severity_counts['medium'] > 5 or avg_cvss >= 4.0:
            return 'medium'
        return 'low'
