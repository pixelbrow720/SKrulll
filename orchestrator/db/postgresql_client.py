"""
PostgreSQL client for the CyberOps Orchestrator.

This module provides a client for interacting with PostgreSQL databases,
handling connection pooling, query execution, and result processing.
"""
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)

try:
    import psycopg2
    from psycopg2 import pool
    from psycopg2.extras import RealDictCursor
    PSYCOPG2_AVAILABLE = True
except ImportError:
    logger.warning("psycopg2 not installed, PostgreSQL functionality will be limited")
    PSYCOPG2_AVAILABLE = False

# Global connection pool
connection_pool = None


def parse_database_url(url: str) -> Dict[str, str]:
    """
    Parse a PostgreSQL database URL into connection parameters.
    
    Args:
        url: Database URL in the format postgresql://user:pass@host:port/dbname
        
    Returns:
        Dictionary of connection parameters
    """
    # Regular expression to parse the URL
    pattern = r'postgresql://(?:(?P<user>[^:@]+)(?::(?P<password>[^@]+))?@)?(?P<host>[^:/]+)(?::(?P<port>\d+))?/(?P<dbname>[^?]+)'
    match = re.match(pattern, url)
    
    if not match:
        raise ValueError(f"Invalid PostgreSQL URL format: {url}")
    
    params = match.groupdict()
    # Remove None values
    return {k: v for k, v in params.items() if v is not None}


def initialize_pool(min_connections: int = 1, 
                   max_connections: int = 10,
                   **kwargs) -> bool:
    """
    Initialize the PostgreSQL connection pool.
    
    Args:
        min_connections: Minimum number of connections in the pool
        max_connections: Maximum number of connections in the pool
        **kwargs: Additional connection parameters
        
    Returns:
        True if successful, False otherwise
    """
    global connection_pool
    
    if not PSYCOPG2_AVAILABLE:
        logger.error("Cannot initialize PostgreSQL pool: psycopg2 not installed")
        return False
    
    try:
        # Check if we have a DATABASE_URL environment variable or in kwargs
        database_url = kwargs.get('url', os.environ.get('DATABASE_URL'))
        
        if database_url:
            logger.info("Using DATABASE_URL for PostgreSQL connection")
            
            try:
                # Parse the URL into connection parameters
                conn_params = parse_database_url(database_url)
                logger.debug(f"Parsed connection parameters: {conn_params}")
                
                # Create the connection pool with the parsed parameters
                connection_pool = pool.ThreadedConnectionPool(
                    min_connections,
                    max_connections,
                    **conn_params
                )
            except ValueError as e:
                logger.warning(f"Failed to parse DATABASE_URL: {str(e)}")
                logger.warning("Falling back to using the URL directly")
                
                # Fall back to using the URL directly if parsing fails
                connection_pool = pool.ThreadedConnectionPool(
                    min_connections, 
                    max_connections,
                    database_url
                )
        else:
            # Use environment variables or provided parameters
            host = kwargs.get('host', os.environ.get('PGHOST', 'localhost'))
            port = kwargs.get('port', os.environ.get('PGPORT', '5432'))
            database = kwargs.get('database', os.environ.get('PGDATABASE', 'cyberops'))
            user = kwargs.get('user', os.environ.get('PGUSER', 'postgres'))
            password = kwargs.get('password', os.environ.get('PGPASSWORD', ''))
            
            logger.info(f"Connecting to PostgreSQL database at {host}:{port}/{database}")
            connection_pool = pool.ThreadedConnectionPool(
                min_connections,
                max_connections,
                host=host,
                port=port,
                database=database,
                user=user,
                password=password
            )
        
        logger.info("PostgreSQL connection pool initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize PostgreSQL connection pool: {str(e)}", exc_info=True)
        return False


def get_connection():
    """
    Get a connection from the pool.
    
    Returns:
        Database connection
    
    Raises:
        RuntimeError: If the pool is not initialized
    """
    global connection_pool
    
    if connection_pool is None:
        if not initialize_pool():
            raise RuntimeError("PostgreSQL connection pool not initialized")
    
    return connection_pool.getconn()


def release_connection(conn):
    """
    Release a connection back to the pool.
    
    Args:
        conn: Database connection to release
    """
    global connection_pool
    
    if connection_pool is not None:
        connection_pool.putconn(conn)


def execute_query(query: str, 
                 params: Optional[Union[List, Tuple, Dict]] = None, 
                 fetch: bool = True) -> Union[List[Dict[str, Any]], int, None]:
    """
    Execute a SQL query and return the results.
    
    Args:
        query: SQL query string
        params: Query parameters
        fetch: Whether to fetch and return results
        
    Returns:
        List of result rows as dictionaries, row count for non-query statements,
        or None on error
    """
    conn = None
    try:
        conn = get_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query, params)
            
            if fetch:
                results = cursor.fetchall()
                return [dict(row) for row in results]
            else:
                return cursor.rowcount
    except Exception as e:
        logger.error(f"Error executing query: {str(e)}", exc_info=True)
        return None
    finally:
        if conn:
            release_connection(conn)


def check_connection() -> bool:
    """
    Check if the PostgreSQL connection is working.
    
    Returns:
        True if connection is working, False otherwise
    """
    if not PSYCOPG2_AVAILABLE:
        return False
        
    try:
        result = execute_query("SELECT 1")
        return result is not None and len(result) > 0
    except Exception as e:
        logger.error(f"PostgreSQL connection check failed: {str(e)}", exc_info=True)
        return False


def close_pool():
    """Close the PostgreSQL connection pool."""
    global connection_pool
    
    if connection_pool is not None:
        connection_pool.closeall()
        connection_pool = None
        logger.info("PostgreSQL connection pool closed")
