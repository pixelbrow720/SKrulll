"""
Neo4j client for the SKrulll Orchestrator.

This module provides a client for interacting with Neo4j graph databases,
handling connection, queries, and graph operations.
"""
import logging
import os
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)

try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    logger.warning("neo4j-python-driver not installed, Neo4j functionality will be limited")
    NEO4J_AVAILABLE = False

# Global driver instance
driver = None


def initialize_driver(**kwargs) -> bool:
    """
    Initialize the Neo4j driver.
    
    Args:
        **kwargs: Additional connection parameters
        
    Returns:
        True if successful, False otherwise
    """
    global driver
    
    if not NEO4J_AVAILABLE:
        logger.error("Cannot initialize Neo4j driver: neo4j-python-driver not installed")
        return False
    
    try:
        # Use environment variables or provided parameters
        uri = kwargs.get('uri', os.environ.get('NEO4J_URI', 'bolt://localhost:7687'))
        username = kwargs.get('username', os.environ.get('NEO4J_USERNAME', 'neo4j'))
        password = kwargs.get('password', os.environ.get('NEO4J_PASSWORD', ''))
        
        logger.info(f"Connecting to Neo4j at {uri}")
        driver = GraphDatabase.driver(uri, auth=(username, password))
        
        # Test connection
        with driver.session() as session:
            result = session.run("RETURN 1 AS num")
            value = result.single().get("num")
            assert value == 1
        
        logger.info("Neo4j driver initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize Neo4j driver: {str(e)}", exc_info=True)
        driver = None
        return False


def get_driver():
    """
    Get the Neo4j driver instance.
    
    Returns:
        Neo4j driver
        
    Raises:
        RuntimeError: If the driver is not initialized
    """
    global driver
    
    if driver is None:
        if not initialize_driver():
            raise RuntimeError("Neo4j driver not initialized")
    
    return driver


def run_query(query: str, parameters: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """
    Run a Cypher query and return the results.
    
    Args:
        query: Cypher query string
        parameters: Query parameters
        
    Returns:
        List of result records as dictionaries
    """
    try:
        with get_driver().session() as session:
            result = session.run(query, parameters or {})
            return [record.data() for record in result]
    except Exception as e:
        logger.error(f"Error executing Neo4j query: {str(e)}", exc_info=True)
        return []


def create_node(label: str, properties: Dict[str, Any]) -> Optional[int]:
    """
    Create a node in the graph.
    
    Args:
        label: Node label
        properties: Node properties
        
    Returns:
        Node ID if successful, None otherwise
    """
    try:
        query = f"CREATE (n:{label} $props) RETURN id(n) AS node_id"
        result = run_query(query, {'props': properties})
        if result and 'node_id' in result[0]:
            return result[0]['node_id']
        return None
    except Exception as e:
        logger.error(f"Error creating Neo4j node: {str(e)}", exc_info=True)
        return None


def create_relationship(start_node_id: int, 
                       end_node_id: int, 
                       relationship_type: str, 
                       properties: Dict[str, Any] = None) -> bool:
    """
    Create a relationship between two nodes.
    
    Args:
        start_node_id: ID of the start node
        end_node_id: ID of the end node
        relationship_type: Relationship type
        properties: Relationship properties
        
    Returns:
        True if successful, False otherwise
    """
    try:
        query = f"""
        MATCH (a), (b)
        WHERE id(a) = $start_id AND id(b) = $end_id
        CREATE (a)-[r:{relationship_type} $props]->(b)
        RETURN id(r) AS rel_id
        """
        result = run_query(query, {
            'start_id': start_node_id,
            'end_id': end_node_id,
            'props': properties or {}
        })
        return result and 'rel_id' in result[0]
    except Exception as e:
        logger.error(f"Error creating Neo4j relationship: {str(e)}", exc_info=True)
        return False


def find_nodes(label: str, properties: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """
    Find nodes matching the given criteria.
    
    Args:
        label: Node label
        properties: Node properties to match
        
    Returns:
        List of matching nodes
    """
    try:
        if properties:
            # Build where clauses for each property
            where_clauses = []
            params = {}
            for i, (key, value) in enumerate(properties.items()):
                param_name = f"prop{i}"
                where_clauses.append(f"n.{key} = ${param_name}")
                params[param_name] = value
                
            where_str = " AND ".join(where_clauses)
            query = f"MATCH (n:{label}) WHERE {where_str} RETURN n"
            return run_query(query, params)
        else:
            query = f"MATCH (n:{label}) RETURN n"
            return run_query(query)
    except Exception as e:
        logger.error(f"Error finding Neo4j nodes: {str(e)}", exc_info=True)
        return []


def check_connection() -> bool:
    """
    Check if the Neo4j connection is working.
    
    Returns:
        True if connection is working, False otherwise
    """
    if not NEO4J_AVAILABLE:
        return False
        
    global driver
    
    if driver is None:
        if not initialize_driver():
            return False
    
    try:
        with driver.session() as session:
            result = session.run("RETURN 1 AS num")
            value = result.single().get("num")
            return value == 1
    except Exception as e:
        logger.error(f"Neo4j connection check failed: {str(e)}", exc_info=True)
        return False


def close_driver():
    """Close the Neo4j driver."""
    global driver
    
    if driver is not None:
        driver.close()
        driver = None
        logger.info("Neo4j driver closed")
