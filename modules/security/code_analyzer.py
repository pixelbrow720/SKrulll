
"""Code analyzer module for detecting security vulnerabilities in source code."""

import ast
import os
import yaml
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

import pylint.lint
import bandit
from bandit.core import manager

logger = logging.getLogger(__name__)

@dataclass
class SecurityIssue:
    file: str
    line: int
    col: int
    severity: str
    message: str
    rule_id: str
    fix_suggestion: Optional[str] = None

class CodeAnalyzer:
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.custom_rules = self._load_custom_rules()
        
    def _load_config(self, config_path: Optional[str]) -> Dict:
        if not config_path:
            config_path = "config/code_analyzer_rules.yml"
            
        try:
            with open(config_path) as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"Failed to load config: {str(e)}")
            return {}
            
    def _load_custom_rules(self) -> List[Dict]:
        rules_dir = self.config.get("custom_rules_dir", "config/security_rules")
        rules = []
        
        if os.path.exists(rules_dir):
            for filename in os.listdir(rules_dir):
                if filename.endswith(".yml"):
                    try:
                        with open(os.path.join(rules_dir, filename)) as f:
                            rules.extend(yaml.safe_load(f))
                    except Exception as e:
                        logger.error(f"Failed to load rule file {filename}: {str(e)}")
                        
        return rules

    def analyze_python_file(self, filepath: str) -> List[SecurityIssue]:
        issues = []
        
        # Run Bandit analysis
        b_mgr = manager.BanditManager()
        b_mgr.discover_files([filepath], recursive=False)
        b_mgr.run_tests()
        
        for issue in b_mgr.get_issue_list():
            issues.append(SecurityIssue(
                file=filepath,
                line=issue.lineno,
                col=0,
                severity=issue.severity,
                message=issue.text,
                rule_id=f"B{issue.test_id}"
            ))
            
        # Parse AST and apply custom rules
        try:
            with open(filepath) as f:
                tree = ast.parse(f.read())
                issues.extend(self._analyze_python_ast(tree, filepath))
        except Exception as e:
            logger.error(f"Failed to parse {filepath}: {str(e)}")
            
        return issues
    
    def _analyze_python_ast(self, tree: ast.AST, filepath: str) -> List[SecurityIssue]:
        issues = []
        
        class SecurityVisitor(ast.NodeVisitor):
            def __init__(self, rules, filepath):
                self.rules = rules
                self.filepath = filepath
                self.issues = []
                
            def visit_Call(self, node):
                for rule in self.rules:
                    if rule["type"] == "dangerous_function":
                        if isinstance(node.func, ast.Name) and node.func.id in rule["functions"]:
                            self.issues.append(SecurityIssue(
                                file=self.filepath,
                                line=node.lineno,
                                col=node.col_offset,
                                severity="HIGH",
                                message=f"Use of dangerous function: {node.func.id}",
                                rule_id=rule["id"],
                                fix_suggestion=rule.get("fix_suggestion")
                            ))
                self.generic_visit(node)
                
        visitor = SecurityVisitor(self.custom_rules, filepath)
        visitor.visit(tree)
        issues.extend(visitor.issues)
        
        return issues
    
    def export_sonarqube(self, issues: List[SecurityIssue]) -> Dict:
        return {
            "issues": [{
                "engineId": "cyberops",
                "ruleId": issue.rule_id,
                "severity": issue.severity,
                "type": "VULNERABILITY",
                "primaryLocation": {
                    "message": issue.message,
                    "filePath": issue.file,
                    "textRange": {
                        "startLine": issue.line,
                        "startColumn": issue.col
                    }
                }
            } for issue in issues]
        }
