
"""
Entry Point Analyzer - Analyzes API endpoints and authentication mechanisms
"""
import logging
import json
import yaml
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import jwt
import requests
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

@dataclass
class Endpoint:
    path: str
    method: str
    auth_type: str
    params: List[str]
    security_level: str
    risk_score: float

class EntryPointAnalyzer:
    def __init__(self, base_url: str, config: Dict[str, Any]):
        self.base_url = base_url
        self.config = config
        self.endpoints: List[Endpoint] = []
    
    def analyze_openapi_spec(self, spec_path: str) -> None:
        """Analyze OpenAPI specification"""
        with open(spec_path) as f:
            if spec_path.endswith('.json'):
                spec = json.load(f)
            else:
                spec = yaml.safe_load(f)
        
        # Process paths and operations
        for path, operations in spec.get('paths', {}).items():
            for method, operation in operations.items():
                if method.lower() not in ['get', 'post', 'put', 'delete', 'patch']:
                    continue
                
                security = operation.get('security', [])
                auth_type = self._determine_auth_type(security, spec)
                params = self._extract_parameters(operation)
                security_level = self._assess_security_level(operation, auth_type)
                risk_score = self._calculate_risk_score(method, auth_type, security_level)
                
                endpoint = Endpoint(
                    path=path,
                    method=method.upper(),
                    auth_type=auth_type,
                    params=params,
                    security_level=security_level,
                    risk_score=risk_score
                )
                self.endpoints.append(endpoint)
    
    def test_oauth2_endpoints(self, client_id: str, client_secret: str) -> Dict[str, Any]:
        """Test OAuth2 authentication endpoints"""
        results = {
            'success': False,
            'issues': []
        }
        
        try:
            # Test token endpoint
            token_url = urljoin(self.base_url, '/oauth/token')
            token_response = requests.post(
                token_url,
                data={
                    'grant_type': 'client_credentials',
                    'client_id': client_id,
                    'client_secret': client_secret
                }
            )
            
            if token_response.status_code == 200:
                results['success'] = True
                token_data = token_response.json()
                
                # Test token usage
                for endpoint in self.endpoints:
                    if endpoint.auth_type == 'oauth2':
                        auth_header = f"Bearer {token_data['access_token']}"
                        response = requests.request(
                            endpoint.method,
                            urljoin(self.base_url, endpoint.path),
                            headers={'Authorization': auth_header}
                        )
                        
                        if response.status_code != 200:
                            results['issues'].append({
                                'endpoint': endpoint.path,
                                'method': endpoint.method,
                                'status_code': response.status_code,
                                'error': 'Failed authentication test'
                            })
            else:
                results['issues'].append({
                    'endpoint': '/oauth/token',
                    'status_code': token_response.status_code,
                    'error': 'Failed to obtain access token'
                })
        
        except Exception as e:
            results['issues'].append({
                'error': f"OAuth2 test failed: {str(e)}"
            })
        
        return results
    
    def test_jwt_endpoints(self) -> Dict[str, Any]:
        """Test JWT authentication endpoints"""
        results = {
            'success': False,
            'issues': []
        }
        
        # Test endpoints with JWT auth
        for endpoint in self.endpoints:
            if endpoint.auth_type == 'jwt':
                try:
                    # Create test JWT
                    test_token = jwt.encode(
                        {'sub': 'test', 'exp': 1735689600},
                        'test_secret',
                        algorithm='HS256'
                    )
                    
                    response = requests.request(
                        endpoint.method,
                        urljoin(self.base_url, endpoint.path),
                        headers={'Authorization': f"Bearer {test_token}"}
                    )
                    
                    # Check responses
                    if response.status_code not in [200, 401]:
                        results['issues'].append({
                            'endpoint': endpoint.path,
                            'method': endpoint.method,
                            'status_code': response.status_code,
                            'error': 'Unexpected response code'
                        })
                
                except Exception as e:
                    results['issues'].append({
                        'endpoint': endpoint.path,
                        'error': f"JWT test failed: {str(e)}"
                    })
        
        results['success'] = len(results['issues']) == 0
        return results
    
    def generate_access_matrix(self) -> Dict[str, List[str]]:
        """Generate access control matrix"""
        matrix = {}
        
        # Group endpoints by auth type and security level
        for endpoint in self.endpoints:
            key = f"{endpoint.auth_type}:{endpoint.security_level}"
            if key not in matrix:
                matrix[key] = []
            matrix[key].append(f"{endpoint.method} {endpoint.path}")
        
        return matrix
    
    def _determine_auth_type(self, security: List[Dict], spec: Dict) -> str:
        """Determine authentication type from OpenAPI security definitions"""
        if not security:
            return 'none'
        
        security_schemes = spec.get('components', {}).get('securitySchemes', {})
        for scheme in security_schemes.values():
            scheme_type = scheme.get('type', '').lower()
            
            if scheme_type == 'oauth2':
                return 'oauth2'
            elif scheme_type == 'http' and scheme.get('scheme', '').lower() == 'bearer':
                return 'jwt'
            elif scheme_type == 'apikey':
                return 'apikey'
        
        return 'unknown'
    
    def _extract_parameters(self, operation: Dict) -> List[str]:
        """Extract parameters from OpenAPI operation"""
        params = []
        for param in operation.get('parameters', []):
            params.append(param.get('name'))
        
        if 'requestBody' in operation:
            schema = operation['requestBody'].get('content', {}).get('application/json', {}).get('schema', {})
            if 'properties' in schema:
                params.extend(schema['properties'].keys())
        
        return params
    
    def _assess_security_level(self, operation: Dict, auth_type: str) -> str:
        """Assess security level of an endpoint"""
        if auth_type == 'none':
            return 'public'
        elif auth_type in ['jwt', 'oauth2']:
            scopes = operation.get('security', [{}])[0].get('oauth2', [])
            if any('admin' in scope for scope in scopes):
                return 'admin'
            return 'authenticated'
        return 'unknown'
    
    def _calculate_risk_score(self, method: str, auth_type: str, security_level: str) -> float:
        """Calculate risk score for an endpoint"""
        score = 0.0
        
        # Method risk
        method_risks = {
            'GET': 1.0,
            'POST': 2.0,
            'PUT': 2.0,
            'DELETE': 3.0,
            'PATCH': 2.0
        }
        score += method_risks.get(method.upper(), 1.0)
        
        # Auth type risk
        auth_risks = {
            'none': 3.0,
            'apikey': 2.0,
            'jwt': 1.0,
            'oauth2': 1.0,
            'unknown': 2.5
        }
        score += auth_risks.get(auth_type, 2.0)
        
        # Security level risk
        security_risks = {
            'public': 3.0,
            'authenticated': 2.0,
            'admin': 1.0,
            'unknown': 2.5
        }
        score += security_risks.get(security_level, 2.0)
        
        return score / 3.0  # Normalize to 0-3 range
