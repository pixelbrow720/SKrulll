"""
MongoDB client for the CyberOps Orchestrator.

This module provides a client for interacting with MongoDB databases,
handling connection, queries, and result processing.
"""
import logging
import os
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)

try:
    import pymongo
    from pymongo import MongoClient
    PYMONGO_AVAILABLE = True
except ImportError:
    logger.warning("pymongo not installed, MongoDB functionality will be limited")
    PYMONGO_AVAILABLE = False

# Global client instance
client = None
db = None


def initialize_client(db_name: str = None, **kwargs) -> bool:
    """
    Initialize the MongoDB client.
    
    Args:
        db_name: Name of the database to use
        **kwargs: Additional connection parameters
        
    Returns:
        True if successful, False otherwise
    """
    global client, db
    
    if not PYMONGO_AVAILABLE:
        logger.error("Cannot initialize MongoDB client: pymongo not installed")
        return False
    
    try:
        # Use environment variables or provided parameters
        host = kwargs.get('host', os.environ.get('MONGODB_HOST', 'localhost'))
        port = int(kwargs.get('port', os.environ.get('MONGODB_PORT', '27017')))
        username = kwargs.get('username', os.environ.get('MONGODB_USERNAME'))
        password = kwargs.get('password', os.environ.get('MONGODB_PASSWORD'))
        database = db_name or kwargs.get('database', os.environ.get('MONGODB_DATABASE', 'cyberops'))
        
        # Construct connection string
        if username and password:
            uri = f"mongodb://{username}:{password}@{host}:{port}/{database}"
        else:
            uri = f"mongodb://{host}:{port}/{database}"
            
        # Check if we have a MONGODB_URI environment variable
        mongodb_uri = os.environ.get('MONGODB_URI')
        if mongodb_uri:
            logger.info("Using MONGODB_URI environment variable for MongoDB connection")
            uri = mongodb_uri
        
        logger.info(f"Connecting to MongoDB at {host}:{port}/{database}")
        client = MongoClient(uri)
        db = client[database]
        
        # Test connection
        client.admin.command('ping')
        
        logger.info("MongoDB client initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize MongoDB client: {str(e)}", exc_info=True)
        client = None
        db = None
        return False


def get_collection(collection_name: str):
    """
    Get a reference to a MongoDB collection.
    
    Args:
        collection_name: Name of the collection
        
    Returns:
        MongoDB collection object
        
    Raises:
        RuntimeError: If the client is not initialized
    """
    global db
    
    if db is None:
        if not initialize_client():
            raise RuntimeError("MongoDB client not initialized")
    
    return db[collection_name]


def find_documents(collection_name: str, 
                  query: Dict[str, Any] = None, 
                  projection: Dict[str, Any] = None, 
                  sort: List[tuple] = None,
                  limit: int = 0) -> List[Dict[str, Any]]:
    """
    Find documents in a collection.
    
    Args:
        collection_name: Name of the collection
        query: Query filter
        projection: Fields to include/exclude
        sort: Sort specification
        limit: Maximum number of documents to return
        
    Returns:
        List of documents
    """
    try:
        collection = get_collection(collection_name)
        cursor = collection.find(
            filter=query or {}, 
            projection=projection
        )
        
        if sort:
            cursor = cursor.sort(sort)
            
        if limit > 0:
            cursor = cursor.limit(limit)
            
        return list(cursor)
    except Exception as e:
        logger.error(f"Error finding documents in {collection_name}: {str(e)}", exc_info=True)
        return []


def insert_document(collection_name: str, document: Dict[str, Any]) -> Optional[str]:
    """
    Insert a document into a collection.
    
    Args:
        collection_name: Name of the collection
        document: Document to insert
        
    Returns:
        Document ID if successful, None otherwise
    """
    try:
        collection = get_collection(collection_name)
        result = collection.insert_one(document)
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"Error inserting document into {collection_name}: {str(e)}", exc_info=True)
        return None


def update_document(collection_name: str, 
                   query: Dict[str, Any], 
                   update: Dict[str, Any], 
                   upsert: bool = False) -> int:
    """
    Update documents in a collection.
    
    Args:
        collection_name: Name of the collection
        query: Query filter
        update: Update operations
        upsert: Whether to insert if document doesn't exist
        
    Returns:
        Number of documents modified
    """
    try:
        collection = get_collection(collection_name)
        result = collection.update_many(
            filter=query,
            update=update,
            upsert=upsert
        )
        return result.modified_count
    except Exception as e:
        logger.error(f"Error updating documents in {collection_name}: {str(e)}", exc_info=True)
        return 0


def delete_documents(collection_name: str, query: Dict[str, Any]) -> int:
    """
    Delete documents from a collection.
    
    Args:
        collection_name: Name of the collection
        query: Query filter
        
    Returns:
        Number of documents deleted
    """
    try:
        collection = get_collection(collection_name)
        result = collection.delete_many(filter=query)
        return result.deleted_count
    except Exception as e:
        logger.error(f"Error deleting documents from {collection_name}: {str(e)}", exc_info=True)
        return 0


def check_connection() -> bool:
    """
    Check if the MongoDB connection is working.
    
    Returns:
        True if connection is working, False otherwise
    """
    if not PYMONGO_AVAILABLE:
        return False
        
    global client
    
    if client is None:
        if not initialize_client():
            return False
    
    try:
        client.admin.command('ping')
        return True
    except Exception as e:
        logger.error(f"MongoDB connection check failed: {str(e)}", exc_info=True)
        return False


def close_client():
    """Close the MongoDB client."""
    global client, db
    
    if client is not None:
        client.close()
        client = None
        db = None
        logger.info("MongoDB client closed")
