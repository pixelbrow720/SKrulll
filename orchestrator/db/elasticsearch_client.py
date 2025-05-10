"""
Elasticsearch client for the CyberOps Orchestrator.

This module provides a client for interacting with Elasticsearch,
handling indexing, searching, and aggregating data.
"""
import logging
import os
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)

try:
    from elasticsearch import Elasticsearch
    ELASTICSEARCH_AVAILABLE = True
except ImportError:
    logger.warning("elasticsearch-py not installed, Elasticsearch functionality will be limited")
    ELASTICSEARCH_AVAILABLE = False

# Global client instance
client = None


def initialize_client(**kwargs) -> bool:
    """
    Initialize the Elasticsearch client.
    
    Args:
        **kwargs: Additional connection parameters
        
    Returns:
        True if successful, False otherwise
    """
    global client
    
    if not ELASTICSEARCH_AVAILABLE:
        logger.error("Cannot initialize Elasticsearch client: elasticsearch-py not installed")
        return False
    
    try:
        # Use environment variables or provided parameters
        hosts = kwargs.get('hosts', [os.environ.get('ELASTICSEARCH_HOST', 'localhost:9200')])
        if isinstance(hosts, str):
            hosts = [hosts]
            
        username = kwargs.get('username', os.environ.get('ELASTICSEARCH_USERNAME'))
        password = kwargs.get('password', os.environ.get('ELASTICSEARCH_PASSWORD'))
        
        # Setup client arguments
        client_kwargs = {
            'hosts': hosts
        }
        
        # Add authentication if provided
        if username and password:
            client_kwargs['basic_auth'] = (username, password)
        
        # Add other kwargs
        use_ssl = kwargs.get('use_ssl', os.environ.get('ELASTICSEARCH_USE_SSL', 'false').lower() == 'true')
        if use_ssl:
            client_kwargs['scheme'] = 'https'
            verify_certs = kwargs.get('verify_certs', os.environ.get('ELASTICSEARCH_VERIFY_CERTS', 'true').lower() == 'true')
            client_kwargs['verify_certs'] = verify_certs
        
        logger.info(f"Connecting to Elasticsearch at {', '.join(hosts)}")
        client = Elasticsearch(**client_kwargs)
        
        # Test connection
        info = client.info()
        logger.info(f"Connected to Elasticsearch cluster: {info.get('cluster_name', 'unknown')}")
        
        return True
    except Exception as e:
        logger.error(f"Failed to initialize Elasticsearch client: {str(e)}", exc_info=True)
        client = None
        return False


def get_client():
    """
    Get the Elasticsearch client instance.
    
    Returns:
        Elasticsearch client
        
    Raises:
        RuntimeError: If the client is not initialized
    """
    global client
    
    if client is None:
        if not initialize_client():
            raise RuntimeError("Elasticsearch client not initialized")
    
    return client


def index_document(index_name: str, document: Dict[str, Any], doc_id: str = None) -> bool:
    """
    Index a document in Elasticsearch.
    
    Args:
        index_name: Name of the index
        document: Document to index
        doc_id: Optional document ID
        
    Returns:
        True if successful, False otherwise
    """
    try:
        es = get_client()
        response = es.index(
            index=index_name,
            document=document,
            id=doc_id,
            refresh=True
        )
        return response['result'] in ['created', 'updated']
    except Exception as e:
        logger.error(f"Error indexing document in {index_name}: {str(e)}", exc_info=True)
        return False


def bulk_index(index_name: str, documents: List[Dict[str, Any]]) -> int:
    """
    Bulk index multiple documents.
    
    Args:
        index_name: Name of the index
        documents: List of documents to index
        
    Returns:
        Number of documents successfully indexed
    """
    try:
        from elasticsearch.helpers import bulk
        es = get_client()
        
        # Prepare actions
        actions = [
            {
                '_op_type': 'index',
                '_index': index_name,
                '_source': doc,
                '_id': doc.get('id') if 'id' in doc else None
            }
            for doc in documents
        ]
        
        # Execute bulk operation
        success, failed = bulk(es, actions, refresh=True)
        if failed:
            logger.warning(f"Failed to index {len(failed)} documents")
            
        return success
    except Exception as e:
        logger.error(f"Error bulk indexing documents in {index_name}: {str(e)}", exc_info=True)
        return 0


def search(index_name: str, 
          query: Dict[str, Any], 
          size: int = 10, 
          from_: int = 0, 
          sort: List[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Search for documents in an index.
    
    Args:
        index_name: Name of the index
        query: Elasticsearch query
        size: Number of results to return
        from_: Starting offset
        sort: Sort order
        
    Returns:
        Search results
    """
    try:
        es = get_client()
        body = {
            'query': query,
            'size': size,
            'from': from_
        }
        
        if sort:
            body['sort'] = sort
            
        response = es.search(
            index=index_name,
            body=body
        )
        
        return response
    except Exception as e:
        logger.error(f"Error searching in {index_name}: {str(e)}", exc_info=True)
        return {'hits': {'total': {'value': 0}, 'hits': []}}


def delete_document(index_name: str, doc_id: str) -> bool:
    """
    Delete a document from an index.
    
    Args:
        index_name: Name of the index
        doc_id: Document ID
        
    Returns:
        True if successful, False otherwise
    """
    try:
        es = get_client()
        response = es.delete(
            index=index_name,
            id=doc_id,
            refresh=True
        )
        return response['result'] == 'deleted'
    except Exception as e:
        logger.error(f"Error deleting document {doc_id} from {index_name}: {str(e)}", exc_info=True)
        return False


def create_index(index_name: str, mappings: Dict[str, Any] = None) -> bool:
    """
    Create an Elasticsearch index.
    
    Args:
        index_name: Name of the index
        mappings: Index mappings
        
    Returns:
        True if successful, False otherwise
    """
    try:
        es = get_client()
        
        # Check if index already exists
        if es.indices.exists(index=index_name):
            logger.info(f"Index {index_name} already exists")
            return True
            
        # Create index
        body = {}
        if mappings:
            body['mappings'] = mappings
            
        response = es.indices.create(
            index=index_name,
            body=body
        )
        
        return response.get('acknowledged', False)
    except Exception as e:
        logger.error(f"Error creating index {index_name}: {str(e)}", exc_info=True)
        return False


def check_connection() -> bool:
    """
    Check if the Elasticsearch connection is working.
    
    Returns:
        True if connection is working, False otherwise
    """
    if not ELASTICSEARCH_AVAILABLE:
        return False
        
    global client
    
    if client is None:
        if not initialize_client():
            return False
    
    try:
        info = client.info()
        return 'name' in info
    except Exception as e:
        logger.error(f"Elasticsearch connection check failed: {str(e)}", exc_info=True)
        return False


def close_client():
    """Close the Elasticsearch client."""
    global client
    
    if client is not None:
        client.close()
        client = None
        logger.info("Elasticsearch client closed")
