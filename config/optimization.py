
"""
System optimization utilities for SKrulll.

This module provides utilities for optimizing system resources, database queries,
and application performance. It includes functions for:

- Memory allocation optimization based on system resources
- Database query analysis and optimization
- Caching strategy configuration
- Docker image optimization
- System performance reporting

These utilities help ensure optimal performance of the SKrulll platform
across various deployment environments and workloads.
"""
import logging
import os
import json
import psutil
from pathlib import Path
from typing import Dict, Any, List, Tuple

logger = logging.getLogger(__name__)

def optimize_memory_usage(config: Dict[str, Any], custom_allocations: Dict[str, Any] = None, 
                         config_file: str = None) -> Dict[str, Any]:
    """
    Optimize memory usage based on available system resources and custom allocations.
    
    Args:
        config: Current configuration
        custom_allocations: Optional custom memory allocations to override defaults
            Format: {
                'reserve_percentage': float,  # Percentage of total memory to reserve for OS
                'neo4j_percentage': float,    # Percentage of available memory for Neo4j
                'elasticsearch_percentage': float,  # Percentage for Elasticsearch
                'app_percentage': float,      # Percentage for application
                'mongodb_percentage': float,  # Percentage for MongoDB
                'max_limits': {               # Maximum memory limits regardless of available memory
                    'neo4j': int,             # Max Neo4j memory in MB
                    'elasticsearch': int,     # Max Elasticsearch memory in MB
                    'app': int,               # Max application memory in MB
                    'mongodb': int            # Max MongoDB memory in MB
                }
            }
        config_file: Optional path to a JSON file with custom allocations
        
    Returns:
        Updated configuration with optimized memory settings
    """
    try:
        # Load custom allocations from file if provided
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    file_allocations = json.load(f)
                    # Merge with provided custom allocations, with provided taking precedence
                    if custom_allocations:
                        # Deep merge the dictionaries
                        for key, value in file_allocations.items():
                            if key not in custom_allocations:
                                custom_allocations[key] = value
                            elif isinstance(value, dict) and isinstance(custom_allocations[key], dict):
                                for subkey, subvalue in value.items():
                                    if subkey not in custom_allocations[key]:
                                        custom_allocations[key][subkey] = subvalue
                    else:
                        custom_allocations = file_allocations
                    
                    logger.info(f"Loaded custom memory allocations from {config_file}")
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load custom allocations from {config_file}: {str(e)}")
        
        # Get system memory information
        mem_info = psutil.virtual_memory()
        total_mem_mb = mem_info.total / (1024 * 1024)  # Convert to MB
        available_mem_mb = mem_info.available / (1024 * 1024)  # Available memory
        
        logger.info(f"Total system memory: {total_mem_mb:.2f} MB, Available: {available_mem_mb:.2f} MB")
        
        # Get CPU count for better scaling decisions
        cpu_count = psutil.cpu_count(logical=True)
        physical_cpu_count = psutil.cpu_count(logical=False) or 1
        
        logger.info(f"CPU cores: {physical_cpu_count} physical, {cpu_count} logical")
        
        # Initialize custom allocations if not provided
        if custom_allocations is None:
            custom_allocations = {}
        
        # Calculate memory limits for different components
        # Reserve memory for OS and other processes - dynamic based on total memory
        # For smaller systems, reserve a higher percentage
        if 'reserve_percentage' in custom_allocations:
            reserve_percentage = custom_allocations['reserve_percentage']
        else:
            # More dynamic scaling based on total memory
            if total_mem_mb < 2048:  # Less than 2GB
                reserve_percentage = 0.30  # Reserve 30%
            elif total_mem_mb < 4096:  # Less than 4GB
                reserve_percentage = 0.25  # Reserve 25%
            elif total_mem_mb < 8192:  # Less than 8GB
                reserve_percentage = 0.20  # Reserve 20%
            elif total_mem_mb < 16384:  # Less than 16GB
                reserve_percentage = 0.15  # Reserve 15%
            else:
                reserve_percentage = 0.10  # Reserve 10%
        
        # Calculate reserved memory, but ensure we don't reserve too much on large systems
        reserved_mem = min(total_mem_mb * reserve_percentage, 4096 + (total_mem_mb * 0.05))
        available_mem = total_mem_mb - reserved_mem
        
        # Get max limits from custom allocations or use defaults
        max_limits = custom_allocations.get('max_limits', {})
        max_neo4j = max_limits.get('neo4j', 8192)  # Default 8GB max
        max_elasticsearch = max_limits.get('elasticsearch', 31744)  # Default 31GB max (ES recommendation)
        max_app = max_limits.get('app', 4096)  # Default 4GB max
        max_mongodb = max_limits.get('mongodb', 4096)  # Default 4GB max
        
        # Calculate optimal heap sizes based on application needs and available memory
        # Neo4j - scales with graph size and query complexity
        neo4j_percentage = custom_allocations.get(
            'neo4j_percentage', 
            min(0.4, max(0.25, 0.3 * (physical_cpu_count / 4)))
        )
        # Adjust Neo4j memory based on workload type if specified
        workload_type = custom_allocations.get('workload_type', 'balanced')
        if workload_type == 'graph_intensive':
            neo4j_percentage = min(0.5, neo4j_percentage * 1.25)
        elif workload_type == 'search_intensive':
            neo4j_percentage = max(0.2, neo4j_percentage * 0.8)
            
        neo4j_mem = min(max_neo4j, max(1024, available_mem * neo4j_percentage))
        
        # Elasticsearch - scales with index size and search complexity
        es_percentage = custom_allocations.get(
            'elasticsearch_percentage',
            min(0.3, max(0.15, 0.2 * (physical_cpu_count / 4)))
        )
        # Adjust ES memory based on workload type
        if workload_type == 'search_intensive':
            es_percentage = min(0.5, es_percentage * 1.25)
        elif workload_type == 'graph_intensive':
            es_percentage = max(0.15, es_percentage * 0.8)
            
        elasticsearch_mem = min(max_elasticsearch, max(512, available_mem * es_percentage))
        
        # Application memory - scales with concurrent users and operations
        app_percentage = custom_allocations.get(
            'app_percentage',
            min(0.2, max(0.1, 0.15 * (cpu_count / 8)))
        )
        # Adjust app memory based on expected concurrent users
        concurrent_users = custom_allocations.get('concurrent_users', 10)
        if concurrent_users > 50:
            app_percentage = min(0.3, app_percentage * 1.2)
            
        app_mem = min(max_app, max(512, available_mem * app_percentage))
        
        # MongoDB - scales with dataset size and query complexity
        mongodb_percentage = custom_allocations.get(
            'mongodb_percentage',
            min(0.2, max(0.1, 0.15 * (physical_cpu_count / 4)))
        )
        # Adjust MongoDB memory based on data size if specified
        data_size_gb = custom_allocations.get('data_size_gb', 0)
        if data_size_gb > 10:
            mongodb_percentage = min(0.3, mongodb_percentage * (1 + (data_size_gb / 100)))
            
        mongodb_mem = min(max_mongodb, max(256, available_mem * mongodb_percentage))
        
        # Check if total allocated memory exceeds available memory
        total_allocated = neo4j_mem + elasticsearch_mem + app_mem + mongodb_mem
        if total_allocated > available_mem * 1.1:  # Allow 10% overcommit
            logger.warning(f"Total allocated memory ({total_allocated:.0f}MB) exceeds available memory ({available_mem:.0f}MB)")
            # Scale down proportionally
            scale_factor = available_mem / total_allocated
            neo4j_mem *= scale_factor
            elasticsearch_mem *= scale_factor
            app_mem *= scale_factor
            mongodb_mem *= scale_factor
            logger.info(f"Scaled down memory allocations by factor of {scale_factor:.2f}")
        
        # Update configuration with optimized values
        optimized_config = config.copy()
        
        # Create explicit memory configuration section
        if 'memory_configuration' not in optimized_config:
            optimized_config['memory_configuration'] = {}
            
        # Update Neo4j memory settings
        if 'database' in optimized_config and 'neo4j' in optimized_config['database']:
            # Add explicit memory configuration
            optimized_config['memory_configuration']['neo4j'] = {
                'memory_mb': int(neo4j_mem),
                'heap_size_mb': int(neo4j_mem),
                'gc_settings': {
                    'use_g1gc': True,
                    'exit_on_oom': True
                }
            }
            
            # Add GC tuning parameters based on memory size
            if neo4j_mem >= 4096:
                # For larger heaps, use G1GC with more tuning
                optimized_config['memory_configuration']['neo4j']['gc_settings'].update({
                    'g1_heap_region_size_mb': 16,
                    'parallel_ref_proc_enabled': True,
                    'disable_explicit_gc': True,
                    'max_gc_pause_millis': 200,
                    'g1_heap_waste_percent': 5
                })
                
                # Keep java_opts for backward compatibility
                optimized_config['database']['neo4j']['java_opts'] = (
                    f"-Xms{neo4j_mem:.0f}m -Xmx{neo4j_mem:.0f}m "
                    f"-XX:+UseG1GC -XX:G1HeapRegionSize=16m "
                    f"-XX:+ParallelRefProcEnabled -XX:+DisableExplicitGC "
                    f"-XX:MaxGCPauseMillis=200 -XX:G1HeapWastePercent=5 "
                    f"-XX:+ExitOnOutOfMemoryError"
                )
            else:
                # For smaller heaps, simpler settings
                optimized_config['memory_configuration']['neo4j']['gc_settings'].update({
                    'parallel_ref_proc_enabled': True
                })
                
                # Keep java_opts for backward compatibility
                optimized_config['database']['neo4j']['java_opts'] = (
                    f"-Xms{neo4j_mem:.0f}m -Xmx{neo4j_mem:.0f}m "
                    f"-XX:+UseG1GC -XX:+ParallelRefProcEnabled "
                    f"-XX:+ExitOnOutOfMemoryError"
                )
        
        # Update Elasticsearch memory settings
        if 'database' in optimized_config and 'elasticsearch' in optimized_config['database']:
            # Add explicit memory configuration
            optimized_config['memory_configuration']['elasticsearch'] = {
                'memory_mb': int(elasticsearch_mem),
                'heap_size_mb': int(elasticsearch_mem),
                'gc_settings': {
                    'use_g1gc': True,
                    'heap_dump_on_oom': True
                }
            }
            
            # Add GC tuning parameters based on memory size
            if elasticsearch_mem >= 8192:
                # For larger heaps, more detailed tuning
                optimized_config['memory_configuration']['elasticsearch']['gc_settings'].update({
                    'g1_reserve_percent': 25,
                    'initiating_heap_occupancy_percent': 30,
                    'max_gc_pause_millis': 200
                })
                
                # Keep java_opts for backward compatibility
                optimized_config['database']['elasticsearch']['java_opts'] = (
                    f"-Xms{elasticsearch_mem:.0f}m -Xmx{elasticsearch_mem:.0f}m "
                    f"-XX:+UseG1GC -XX:G1ReservePercent=25 "
                    f"-XX:InitiatingHeapOccupancyPercent=30 "
                    f"-XX:MaxGCPauseMillis=200 "
                    f"-XX:+HeapDumpOnOutOfMemoryError"
                )
            else:
                # Keep java_opts for backward compatibility
                optimized_config['database']['elasticsearch']['java_opts'] = (
                    f"-Xms{elasticsearch_mem:.0f}m -Xmx{elasticsearch_mem:.0f}m "
                    f"-XX:+UseG1GC -XX:+HeapDumpOnOutOfMemoryError"
                )
        
        # Update application memory settings
        optimized_config['app'] = optimized_config.get('app', {})
        optimized_config['app']['memory_limit'] = f"{app_mem:.0f}m"
        
        # Add explicit memory configuration for app
        optimized_config['memory_configuration']['app'] = {
            'memory_mb': int(app_mem),
            'container_limit_mb': int(app_mem)
        }
        
        # Add MongoDB memory settings if not present
        if 'database' in optimized_config:
            if 'mongodb' not in optimized_config['database']:
                optimized_config['database']['mongodb'] = {}
            
            if 'mongodb' in optimized_config['database']:
                # Add explicit memory configuration
                optimized_config['memory_configuration']['mongodb'] = {
                    'memory_mb': int(mongodb_mem),
                    'wiredtiger_cache_mb': int(mongodb_mem)
                }
                
                # Keep old format for backward compatibility
                optimized_config['database']['mongodb']['wiredTiger_cache_size'] = f"{mongodb_mem:.0f}MB"
                
                # Add additional MongoDB optimizations based on available memory
                if mongodb_mem >= 2048:
                    # For larger memory, add more detailed settings
                    optimized_config['memory_configuration']['mongodb'].update({
                        'wiredtiger_cache_gb': mongodb_mem / 1024,
                        'max_connections': min(2000, int(mongodb_mem / 10)),
                        'allow_table_scan': True,
                        'journal_commit_interval_ms': 100
                    })
                    
                    # Keep old format for backward compatibility
                    optimized_config['database']['mongodb']['options'] = {
                        'wiredTigerCacheSizeGB': mongodb_mem / 1024,
                        'maxConns': min(2000, int(mongodb_mem / 10)),  # Scale connections with memory
                        'notablescan': 'false',  # Allow table scans
                        'journalCommitInterval': 100  # ms, lower for better durability
                    }
        
        logger.info(
            f"Memory allocation: Neo4j={neo4j_mem:.0f}MB, "
            f"Elasticsearch={elasticsearch_mem:.0f}MB, "
            f"App={app_mem:.0f}MB, "
            f"MongoDB={mongodb_mem:.0f}MB"
        )
        
        # Save the optimized allocations for reference
        optimized_config['memory_optimization'] = {
            'timestamp': datetime.datetime.now().isoformat(),
            'total_memory_mb': total_mem_mb,
            'available_memory_mb': available_mem_mb,
            'reserved_memory_mb': reserved_mem,
            'allocations': {
                'neo4j_mb': neo4j_mem,
                'elasticsearch_mb': elasticsearch_mem,
                'app_mb': app_mem,
                'mongodb_mb': mongodb_mem
            },
            'cpu_info': {
                'physical_cores': physical_cpu_count,
                'logical_cores': cpu_count
            }
        }
        
        return optimized_config
        
    except Exception as e:
        logger.error(f"Error optimizing memory usage: {str(e)}", exc_info=True)
        # Return original config if optimization fails
        return config

def lint_database_queries(db_type: str, queries_file: str, explain_output_file: str = None) -> List[Tuple[str, str, Dict[str, Any]]]:
    """
    Analyze database queries and provide linting suggestions with specific improvements.
    This function acts as a query linter, identifying common anti-patterns and suggesting
    improvements based on string pattern matching.
    
    Args:
        db_type: Database type (postgresql, mongodb, neo4j)
        queries_file: Path to JSON file with queries to analyze
        explain_output_file: Optional path to a file containing EXPLAIN output for the queries
        
    Returns:
        List of tuples (original_query, linting_suggestion, improvement_metrics)
    """
    optimization_suggestions = []
    
    try:
        with open(queries_file, 'r') as f:
            queries = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.error(f"Failed to load queries file: {e}")
        return optimization_suggestions
    
    # Load explain output if available
    explain_data = {}
    if explain_output_file and os.path.exists(explain_output_file):
        try:
            with open(explain_output_file, 'r') as f:
                explain_data = json.load(f)
            logger.info(f"Loaded query explain data from {explain_output_file}")
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load explain data from {explain_output_file}: {str(e)}")
    
    for query in queries:
        original = query.get('query', '')
        query_id = query.get('id', '')
        context = query.get('context', {})
        
        if not original:
            continue
            
        suggestion = ""
        improvement_metrics = {
            "estimated_improvement": "Unknown",
            "optimization_type": [],
            "risk_level": "Low"
        }
        
        # Get explain data for this query if available
        query_explain = None
        if query_id and query_id in explain_data:
            query_explain = explain_data[query_id]
        
        # Generate database-specific linting suggestions with concrete improvements
        if db_type == 'postgresql':
            suggestion, improvement_metrics = _lint_postgresql_query(original, query_explain, context)
                
        elif db_type == 'mongodb':
            suggestion, improvement_metrics = _lint_mongodb_query(original, query_explain, context)
                
        elif db_type == 'neo4j':
            suggestion, improvement_metrics = _lint_neo4j_query(original, query_explain, context)
        
        if suggestion:
            optimization_suggestions.append((original, suggestion, improvement_metrics))
            logger.info(f"Generated optimization suggestion for query: {original[:50]}...")
    
    return optimization_suggestions

def _lint_postgresql_query(query: str, query_explain: Optional[Dict[str, Any]] = None, 
                          context: Optional[Dict[str, Any]] = None) -> Tuple[str, Dict[str, Any]]:
    """
    Analyze and lint a PostgreSQL query.
    
    Args:
        query: The SQL query to optimize
        query_explain: Optional EXPLAIN output for the query
        context: Optional context information about the query
        
    Returns:
        Tuple of (optimization_suggestion, improvement_metrics)
    """
    suggestion = ""
    metrics = {
        "estimated_improvement": "Unknown",
        "optimization_type": [],
        "risk_level": "Low"
    }
    
    # Check for common inefficient patterns
    query_lower = query.lower()
    
    # Check for SELECT * without WHERE clause
    if "select *" in query_lower and "where" not in query_lower:
        suggestion += (
            "Avoid using SELECT * without a WHERE clause on large tables:\n"
            "- Add a WHERE clause to filter results\n"
            "- Specify only the columns you need instead of *\n\n"
        )
        metrics["optimization_type"].append("column_selection")
        metrics["estimated_improvement"] = "High"
    
    # Check for missing indexes on JOIN or WHERE
    if "join" in query_lower or "where" in query_lower:
        suggestion += (
            "Ensure proper indexes exist for JOIN and WHERE conditions:\n"
            f"- Analyze the query with EXPLAIN ANALYZE {query}\n"
            "- Look for 'Seq Scan' operations on large tables\n"
            "- Add indexes on columns used in JOIN conditions and WHERE clauses\n\n"
        )
        metrics["optimization_type"].append("indexing")
        metrics["estimated_improvement"] = "Medium to High"
    
    # Check for inefficient LIKE patterns
    if "like" in query_lower and "%'" in query_lower and "'%" in query_lower:
        suggestion += (
            "LIKE with leading wildcards (%text%) cannot use standard indexes:\n"
            "- Consider using a trigram index (pg_trgm) for this query\n"
            "- Or use full-text search with to_tsvector() and to_tsquery() for better performance\n\n"
        )
        metrics["optimization_type"].append("pattern_matching")
        metrics["estimated_improvement"] = "High"
    
    # Check for potential N+1 query patterns
    if "in (select" in query_lower or "exists (select" in query_lower:
        suggestion += (
            "Potential N+1 query pattern detected:\n"
            "- Consider using JOIN instead of IN/EXISTS subqueries\n"
            "- Or use a CTE (WITH clause) to materialize the subquery result once\n\n"
        )
        metrics["optimization_type"].append("query_structure")
        metrics["estimated_improvement"] = "Medium"
    
    # Add general advice if no specific issues found
    if not suggestion:
        suggestion = (
            "Use EXPLAIN ANALYZE to identify bottlenecks:\n"
            f"EXPLAIN ANALYZE {query}\n\n"
            "General optimization tips:\n"
            "- Add appropriate indexes based on WHERE clauses and join conditions\n"
            "- Review query plan for sequential scans on large tables\n"
            "- Consider partitioning large tables if queries filter on a specific column\n"
            "- Use LIMIT with ORDER BY to avoid sorting the entire result set\n"
        )
        metrics["optimization_type"].append("general")
        metrics["estimated_improvement"] = "Unknown"
    
    return suggestion, metrics

def _lint_mongodb_query(query: str, query_explain: Optional[Dict[str, Any]] = None,
                       context: Optional[Dict[str, Any]] = None) -> Tuple[str, Dict[str, Any]]:
    """
    Analyze and lint a MongoDB query.
    
    Args:
        query: The MongoDB query to optimize (as a string representation)
        query_explain: Optional explain output for the query
        context: Optional context information about the query
        
    Returns:
        Tuple of (optimization_suggestion, improvement_metrics)
    """
    suggestion = ""
    metrics = {
        "estimated_improvement": "Unknown",
        "optimization_type": [],
        "risk_level": "Low"
    }
    
    # Check for common inefficient patterns
    query_lower = query.lower()
    
    # Check for queries without projection
    if ".find(" in query_lower and not ".find({" in query_lower and not ".find(" in query_lower and "," in query_lower:
        suggestion += (
            "Use projection to limit returned fields:\n"
            "- Modify your query to specify only needed fields\n"
            "- Example: db.collection.find({...}, {field1: 1, field2: 1})\n\n"
        )
        metrics["optimization_type"].append("projection")
        metrics["estimated_improvement"] = "Medium"
    
    # Check for queries with sort without index
    if ".sort(" in query_lower:
        suggestion += (
            "Ensure indexes exist for sort operations:\n"
            "- Create an index for the fields used in sort()\n"
            "- For compound sorts, create a compound index in the same order\n"
            "- Use explain() to verify the index is being used\n\n"
        )
        metrics["optimization_type"].append("indexing")
        metrics["estimated_improvement"] = "High"
    
    # Check for regex queries
    if "regex" in query_lower or "/$" in query_lower:
        suggestion += (
            "Regex queries, especially with leading wildcards, can be slow:\n"
            "- Use text indexes for text search instead of regex\n"
            "- If regex is necessary, ensure it has an anchored prefix (e.g., /^prefix/)\n"
            "- Consider using Atlas Search for more advanced text search capabilities\n\n"
        )
        metrics["optimization_type"].append("pattern_matching")
        metrics["estimated_improvement"] = "Medium to High"
    
    # Check for potential aggregation pipeline optimizations
    if ".aggregate(" in query_lower:
        suggestion += (
            "Optimize aggregation pipelines:\n"
            "- Place $match and $project stages early in the pipeline to reduce documents processed\n"
            "- Use $limit and $skip with caution, especially with large offsets\n"
            "- Consider using $indexStats to verify index usage\n\n"
        )
        metrics["optimization_type"].append("aggregation")
        metrics["estimated_improvement"] = "Medium"
    
    # Add general advice if no specific issues found
    if not suggestion:
        suggestion = (
            "Use explain() to analyze query performance:\n"
            "db.collection.explain('executionStats').find(...)\n\n"
            "General optimization tips:\n"
            "- Ensure proper indexes exist for query filters and sort operations\n"
            "- Use projection to limit returned fields\n"
            "- Consider using covered queries (queries satisfied entirely by an index)\n"
            "- For large result sets, use cursor.batchSize() to control memory usage\n"
        )
        metrics["optimization_type"].append("general")
        metrics["estimated_improvement"] = "Unknown"
    
    return suggestion, metrics

def _lint_neo4j_query(query: str, query_explain: Optional[Dict[str, Any]] = None,
                     context: Optional[Dict[str, Any]] = None) -> Tuple[str, Dict[str, Any]]:
    """
    Analyze and lint a Neo4j Cypher query.
    
    Args:
        query: The Cypher query to optimize
        query_explain: Optional PROFILE or EXPLAIN output for the query
        context: Optional context information about the query
        
    Returns:
        Tuple of (optimization_suggestion, improvement_metrics)
    """
    suggestion = ""
    metrics = {
        "estimated_improvement": "Unknown",
        "optimization_type": [],
        "risk_level": "Low"
    }
    
    # Check for common inefficient patterns
    query_lower = query.lower()
    
    # Check for unbounded pattern matching
    if "-[" in query_lower and "*]" in query_lower and not "*1.." in query_lower:
        suggestion += (
            "Unbounded variable-length pattern matching can be expensive:\n"
            "- Add an upper bound to limit path length (e.g., *1..5 instead of *)\n"
            "- Use APOC path expanders for more control over traversal\n"
            "- Consider using shortestPath() or allShortestPaths() for path finding\n\n"
        )
        metrics["optimization_type"].append("path_traversal")
        metrics["estimated_improvement"] = "High"
        metrics["risk_level"] = "Medium"
    
    # Check for missing WHERE clauses in large scans
    if "match (n)" in query_lower and "where" not in query_lower:
        suggestion += (
            "Scanning all nodes without a filter can be expensive:\n"
            "- Add a label to the node pattern: MATCH (n:Label)\n"
            "- Add a WHERE clause to filter nodes\n"
            "- Use an indexed property if available\n\n"
        )
        metrics["optimization_type"].append("node_filtering")
        metrics["estimated_improvement"] = "Very High"
        metrics["risk_level"] = "High"
    
    # Check for COLLECT and UNWIND operations on large datasets
    if "collect(" in query_lower and "unwind" in query_lower:
        suggestion += (
            "COLLECT followed by UNWIND can consume a lot of memory:\n"
            "- Consider if this pattern can be avoided by restructuring the query\n"
            "- Use APOC procedures for batching if processing large amounts of data\n\n"
        )
        metrics["optimization_type"].append("memory_usage")
        metrics["estimated_improvement"] = "Medium"
    
    # Check for missing indexes on properties used in WHERE
    if "where" in query_lower:
        suggestion += (
            "Ensure indexes exist for properties used in WHERE clauses:\n"
            "- Create indexes for properties used for filtering\n"
            "- Use PROFILE to verify index usage\n"
            "- Consider composite indexes for multi-property filters\n\n"
        )
        metrics["optimization_type"].append("indexing")
        metrics["estimated_improvement"] = "High"
    
    # Add general advice if no specific issues found
    if not suggestion:
        suggestion = (
            "Use PROFILE to analyze query performance:\n"
            f"PROFILE {query}\n\n"
            "General optimization tips:\n"
            "- Add appropriate indexes and constraints for properties used in filtering\n"
            "- Review query plan for full node/relationship scans on large datasets\n"
            "- Use parameters instead of literals for better query plan caching\n"
            "- Consider APOC procedures for complex operations\n"
        )
        metrics["optimization_type"].append("general")
        metrics["estimated_improvement"] = "Unknown"
    
    return suggestion, metrics

def setup_caching_strategy(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Configure caching strategy based on application needs.
    
    Args:
        config: Current configuration
        
    Returns:
        Updated configuration with caching settings
    """
    optimized_config = config.copy()
    
    # Configure Redis caching if available
    cache_config = {
        'enabled': True,
        'type': 'redis',
        'ttl': {
            'vulnerability_data': 3600,  # 1 hour cache for vulnerability data
            'network_map': 1800,         # 30 minutes for network maps
            'api_endpoints': 7200,       # 2 hours for API endpoint data
            'reports': 86400,            # 24 hours for generated reports
            'default': 300               # 5 minutes default cache
        },
        'redis': {
            'host': os.environ.get('REDIS_HOST', 'localhost'),
            'port': int(os.environ.get('REDIS_PORT', 6379)),
            'db': 0,
            'password': os.environ.get('REDIS_PASSWORD', '')
        },
        'memory': {
            'max_size': 128,  # MB
            'cleanup_interval': 300  # seconds
        }
    }
    
    optimized_config['caching'] = cache_config
    
    logger.info("Caching strategy configured")
    return optimized_config

def optimize_docker_images() -> Dict[str, Dict[str, Any]]:
    """
    Generate optimization configurations for Docker images.
    
    Returns:
        Dictionary with optimization settings for each image
    """
    optimizations = {
        'base': {
            'use_alpine': True,
            'multistage_build': True,
            'remove_dev_dependencies': True,
            'compress_layers': True
        },
        'python': {
            'use_slim_variant': True,
            'use_pip_compile': True,
            'remove_tests': True,
            'remove_documentation': True
        },
        'nodejs': {
            'use_node_slim': True,
            'use_npm_ci': True,
            'use_production_flag': True
        },
        'golang': {
            'use_multistage': True,
            'build_flags': '-ldflags="-s -w"',
            'disable_cgo': True
        },
        'rust': {
            'use_multistage': True,
            'use_release_profile': True,
            'strip_binaries': True
        }
    }
    
    return optimizations

def generate_optimization_report(config_path: str, output_path: str) -> None:
    """
    Generate a comprehensive system optimization report with detailed metrics and recommendations.
    
    Args:
        config_path: Path to configuration file
        output_path: Path to save optimization report
    """
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.error(f"Failed to load configuration: {e}")
        return
    
    # System information
    system_info = {
        "cpu": {
            "physical_cores": psutil.cpu_count(logical=False),
            "logical_cores": psutil.cpu_count(logical=True),
            "usage_percent": psutil.cpu_percent(interval=1)
        },
        "memory": {
            "total_mb": psutil.virtual_memory().total / (1024 * 1024),
            "available_mb": psutil.virtual_memory().available / (1024 * 1024),
            "used_percent": psutil.virtual_memory().percent
        },
        "disk": {
            "total_gb": psutil.disk_usage('/').total / (1024 * 1024 * 1024),
            "free_gb": psutil.disk_usage('/').free / (1024 * 1024 * 1024),
            "used_percent": psutil.disk_usage('/').percent
        },
        "platform": {
            "system": os.uname().sysname,
            "release": os.uname().release,
            "version": os.uname().version
        }
    }
    
    # Optimize configuration
    optimized_config = optimize_memory_usage(config)
    optimized_config = setup_caching_strategy(optimized_config)
    
    # Docker optimizations
    docker_optimizations = optimize_docker_images()
    
    # Calculate memory savings
    memory_metrics = _calculate_memory_metrics(config, optimized_config)
    
    # Generate database optimization suggestions
    db_optimization_suggestions = {}
    
    # Check if query files exist for each database type
    query_files = {
        "postgresql": "queries/postgresql_queries.json",
        "mongodb": "queries/mongodb_queries.json",
        "neo4j": "queries/neo4j_queries.json"
    }
    
    for db_type, query_file in query_files.items():
        if os.path.exists(query_file):
            suggestions = lint_database_queries(db_type, query_file)
            if suggestions:
                db_optimization_suggestions[db_type] = [
                    {
                        "original_query": orig,
                        "suggestion": sugg,
                        "metrics": metrics
                    }
                    for orig, sugg, metrics in suggestions
                ]
    
    # Network optimization suggestions
    network_suggestions = _generate_network_suggestions()
    
    # Security optimization suggestions
    security_suggestions = _generate_security_suggestions()
    
    # Generate report
    report = {
        'timestamp': datetime.datetime.now().isoformat(),
        'system_info': system_info,
        'original_config': config,
        'optimized_config': optimized_config,
        'docker_optimizations': docker_optimizations,
        'memory_metrics': memory_metrics,
        'database_optimizations': db_optimization_suggestions,
        'network_optimizations': network_suggestions,
        'security_optimizations': security_suggestions,
        'summary': {
            'memory_savings_mb': memory_metrics['savings_mb'],
            'memory_savings_percentage': memory_metrics['savings_percentage'],
            'optimization_score': _calculate_optimization_score(
                memory_metrics, 
                db_optimization_suggestions,
                network_suggestions,
                security_suggestions
            )
        }
    }
    
    # Save report
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    
    # Save as JSON
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    # Also save a human-readable summary
    summary_path = output_path.replace('.json', '_summary.txt')
    with open(summary_path, 'w') as f:
        f.write("CYBEROPS OPTIMIZATION REPORT SUMMARY\n")
        f.write("===================================\n\n")
        f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("SYSTEM INFORMATION\n")
        f.write(f"CPU: {system_info['cpu']['physical_cores']} physical cores, {system_info['cpu']['logical_cores']} logical cores\n")
        f.write(f"Memory: {system_info['memory']['total_mb']:.0f} MB total, {system_info['memory']['used_percent']}% used\n")
        f.write(f"Disk: {system_info['disk']['total_gb']:.1f} GB total, {system_info['disk']['used_percent']}% used\n\n")
        
        f.write("OPTIMIZATION SUMMARY\n")
        f.write(f"Memory Savings: {memory_metrics['savings_mb']} MB ({memory_metrics['savings_percentage']}%)\n")
        f.write(f"Optimization Score: {report['summary']['optimization_score']}/100\n\n")
        
        f.write("KEY RECOMMENDATIONS\n")
        if network_suggestions:
            f.write("Network Optimizations:\n")
            for i, sugg in enumerate(network_suggestions[:3], 1):
                f.write(f"{i}. {sugg['title']}\n")
            f.write("\n")
        
        if security_suggestions:
            f.write("Security Optimizations:\n")
            for i, sugg in enumerate(security_suggestions[:3], 1):
                f.write(f"{i}. {sugg['title']}\n")
            f.write("\n")
        
        f.write("\nSee full report for detailed recommendations and configuration changes.\n")
    
    logger.info(f"Optimization report saved to {output_path}")
    logger.info(f"Summary report saved to {summary_path}")

def _calculate_memory_metrics(config: Dict[str, Any], optimized_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate memory savings metrics between original and optimized configurations.
    
    Args:
        config: Original configuration
        optimized_config: Optimized configuration
        
    Returns:
        Dictionary with memory metrics
    """
    import re
    
    # Initialize memory counters
    original_memory = 0
    optimized_memory = 0
    component_savings = {}
    
    # Helper function to extract memory values with regex
    def extract_memory(java_opts: str) -> int:
        if not java_opts:
            return 0
        
        # Look for -Xmx pattern followed by a number and m/g/G
        match = re.search(r'-Xmx(\d+)([mMgG])', java_opts)
        if not match:
            return 0
            
        value = int(match.group(1))
        unit = match.group(2).lower()
        
        # Convert to MB
        if unit == 'g':
            return value * 1024
        return value
    
    # Helper function to get memory value from explicit memory configuration
    def get_memory_value(config_dict: Dict[str, Any], component: str) -> int:
        """
        Get memory value from explicit memory configuration.
        
        Args:
            config_dict: Configuration dictionary
            component: Component name
            
        Returns:
            Memory value in MB
        """
        if 'memory_configuration' not in config_dict:
            return 0
            
        if component not in config_dict['memory_configuration']:
            return 0
            
        mem_config = config_dict['memory_configuration'][component]
        
        # Get memory value in MB
        if 'memory_mb' in mem_config:
            return mem_config['memory_mb']
        
        # If memory_mb is not available, try to get it from heap_size_mb
        if 'heap_size_mb' in mem_config:
            return mem_config['heap_size_mb']
            
        return 0
    
    # Extract memory values from explicit memory configuration if available, otherwise fall back to parsing settings
    
    # Neo4j
    neo4j_mem = get_memory_value(config, 'neo4j')
    if neo4j_mem == 0 and 'database' in config and 'neo4j' in config['database']:
        neo4j_opts = config['database']['neo4j'].get('java_opts', '')
        neo4j_mem = extract_memory(neo4j_opts)
    original_memory += neo4j_mem
    
    opt_neo4j_mem = get_memory_value(optimized_config, 'neo4j')
    if opt_neo4j_mem == 0 and 'database' in optimized_config and 'neo4j' in optimized_config['database']:
        opt_neo4j_opts = optimized_config['database']['neo4j'].get('java_opts', '')
        opt_neo4j_mem = extract_memory(opt_neo4j_opts)
    optimized_memory += opt_neo4j_mem
    
    # Calculate savings for Neo4j
    component_savings['neo4j'] = {
        'before': neo4j_mem,
        'after': opt_neo4j_mem,
        'savings': max(0, neo4j_mem - opt_neo4j_mem)
    }
    
    # Elasticsearch
    es_mem = get_memory_value(config, 'elasticsearch')
    if es_mem == 0 and 'database' in config and 'elasticsearch' in config['database']:
        es_opts = config['database']['elasticsearch'].get('java_opts', '')
        es_mem = extract_memory(es_opts)
    original_memory += es_mem
    
    opt_es_mem = get_memory_value(optimized_config, 'elasticsearch')
    if opt_es_mem == 0 and 'database' in optimized_config and 'elasticsearch' in optimized_config['database']:
        opt_es_opts = optimized_config['database']['elasticsearch'].get('java_opts', '')
        opt_es_mem = extract_memory(opt_es_opts)
    optimized_memory += opt_es_mem
    
    # Calculate savings for Elasticsearch
    component_savings['elasticsearch'] = {
        'before': es_mem,
        'after': opt_es_mem,
        'savings': max(0, es_mem - opt_es_mem)
    }
    
    # MongoDB
    mongodb_mem = get_memory_value(config, 'mongodb')
    if mongodb_mem == 0 and 'database' in config and 'mongodb' in config['database']:
        mongo_cache = config['database']['mongodb'].get('wiredTiger_cache_size', '0MB')
        match = re.search(r'(\d+)MB', mongo_cache)
        mongodb_mem = int(match.group(1)) if match else 0
    original_memory += mongodb_mem
    
    opt_mongodb_mem = get_memory_value(optimized_config, 'mongodb')
    if opt_mongodb_mem == 0 and 'database' in optimized_config and 'mongodb' in optimized_config['database']:
        opt_mongo_cache = optimized_config['database']['mongodb'].get('wiredTiger_cache_size', '0MB')
        match = re.search(r'(\d+)MB', opt_mongo_cache)
        opt_mongodb_mem = int(match.group(1)) if match else 0
    optimized_memory += opt_mongodb_mem
    
    # Calculate savings for MongoDB
    component_savings['mongodb'] = {
        'before': mongodb_mem,
        'after': opt_mongodb_mem,
        'savings': max(0, mongodb_mem - opt_mongodb_mem)
    }
    
    # Application memory
    app_mem_val = get_memory_value(config, 'app')
    if app_mem_val == 0 and 'app' in config and 'memory_limit' in config['app']:
        app_mem = config['app']['memory_limit']
        match = re.search(r'(\d+)m', app_mem)
        app_mem_val = int(match.group(1)) if match else 0
    original_memory += app_mem_val
    
    opt_app_mem_val = get_memory_value(optimized_config, 'app')
    if opt_app_mem_val == 0 and 'app' in optimized_config and 'memory_limit' in optimized_config['app']:
        opt_app_mem = optimized_config['app']['memory_limit']
        match = re.search(r'(\d+)m', opt_app_mem)
        opt_app_mem_val = int(match.group(1)) if match else 0
    optimized_memory += opt_app_mem_val
    
    # Calculate savings for app
    component_savings['app'] = {
        'before': app_mem_val,
        'after': opt_app_mem_val,
        'savings': max(0, app_mem_val - opt_app_mem_val)
    }
    
    # Calculate total savings
    savings_mb = max(0, original_memory - optimized_memory)
    savings_percentage = round((original_memory - optimized_memory) / original_memory * 100, 2) if original_memory > 0 else 0
    
    return {
        'before_mb': original_memory,
        'after_mb': optimized_memory,
        'savings_mb': savings_mb,
        'savings_percentage': savings_percentage,
        'component_savings': component_savings
    }

def _generate_network_suggestions() -> List[Dict[str, Any]]:
    """
    Generate network optimization suggestions.
    
    Returns:
        List of network optimization suggestions
    """
    return [
        {
            "title": "Implement connection pooling for database connections",
            "description": "Reuse database connections instead of creating new ones for each request",
            "impact": "High",
            "implementation_difficulty": "Medium",
            "recommendation": (
                "Implement connection pooling for all database connections to reduce connection overhead "
                "and improve response times. Configure pool sizes based on expected concurrent users."
            )
        },
        {
            "title": "Enable HTTP/2 for API endpoints",
            "description": "Use HTTP/2 protocol for multiplexing and header compression",
            "impact": "Medium",
            "implementation_difficulty": "Low",
            "recommendation": (
                "Configure your web server to use HTTP/2 protocol which allows multiplexing multiple "
                "requests over a single connection and compresses headers for better performance."
            )
        },
        {
            "title": "Implement request rate limiting",
            "description": "Protect services from excessive requests",
            "impact": "Medium",
            "implementation_difficulty": "Low",
            "recommendation": (
                "Implement rate limiting on API endpoints to prevent abuse and ensure fair resource "
                "allocation. Configure limits based on endpoint sensitivity and resource requirements."
            )
        },
        {
            "title": "Use connection backoff strategy",
            "description": "Implement exponential backoff for connection retries",
            "impact": "Medium",
            "implementation_difficulty": "Low",
            "recommendation": (
                "Implement exponential backoff strategy for connection retries to prevent "
                "overwhelming services during recovery from failures."
            )
        },
        {
            "title": "Optimize Docker network configuration",
            "description": "Use appropriate Docker network drivers and settings",
            "impact": "Medium",
            "implementation_difficulty": "Medium",
            "recommendation": (
                "Configure Docker networks appropriately: use 'host' network for performance-critical "
                "services, ensure proper DNS resolution, and minimize cross-network communication."
            )
        }
    ]

def _generate_security_suggestions() -> List[Dict[str, Any]]:
    """
    Generate security optimization suggestions.
    
    Returns:
        List of security optimization suggestions
    """
    return [
        {
            "title": "Implement least privilege principle for container permissions",
            "description": "Run containers with minimal required permissions",
            "impact": "High",
            "implementation_difficulty": "Medium",
            "recommendation": (
                "Configure containers to run with non-root users, drop unnecessary capabilities, "
                "and use read-only file systems where possible to reduce attack surface."
            )
        },
        {
            "title": "Enable content security policy",
            "description": "Implement CSP headers to prevent XSS attacks",
            "impact": "High",
            "implementation_difficulty": "Medium",
            "recommendation": (
                "Configure Content-Security-Policy headers to restrict resource loading and "
                "script execution to trusted sources only."
            )
        },
        {
            "title": "Implement API rate limiting and throttling",
            "description": "Protect APIs from abuse and DoS attacks",
            "impact": "Medium",
            "implementation_difficulty": "Low",
            "recommendation": (
                "Implement rate limiting and request throttling on all API endpoints to "
                "prevent abuse and denial of service attacks."
            )
        },
        {
            "title": "Use secure communication between services",
            "description": "Encrypt all internal service communication",
            "impact": "High",
            "implementation_difficulty": "Medium",
            "recommendation": (
                "Ensure all inter-service communication is encrypted using TLS, even within "
                "the internal network. Implement mutual TLS (mTLS) for service-to-service authentication."
            )
        },
        {
            "title": "Implement proper secret management",
            "description": "Use a secure vault for storing and accessing secrets",
            "impact": "High",
            "implementation_difficulty": "Medium",
            "recommendation": (
                "Replace hardcoded secrets and environment variables with a secure secret management "
                "solution like HashiCorp Vault or AWS Secrets Manager."
            )
        }
    ]

def _calculate_optimization_score(
    memory_metrics: Dict[str, Any],
    db_optimizations: Dict[str, List[Dict[str, Any]]],
    network_suggestions: List[Dict[str, Any]],
    security_suggestions: List[Dict[str, Any]]
) -> int:
    """
    Calculate an overall optimization score based on various metrics.
    
    Args:
        memory_metrics: Memory optimization metrics
        db_optimizations: Database optimization suggestions
        network_suggestions: Network optimization suggestions
        security_suggestions: Security optimization suggestions
        
    Returns:
        Optimization score (0-100)
    """
    score = 0
    
    # Memory optimization score (0-40 points)
    memory_score = 0
    if memory_metrics['before_mb'] > 0:
        # Calculate percentage of memory saved
        savings_pct = memory_metrics['savings_percentage']
        
        # Score based on savings percentage
        if savings_pct >= 30:
            memory_score = 40
        elif savings_pct >= 20:
            memory_score = 30
        elif savings_pct >= 10:
            memory_score = 20
        elif savings_pct >= 5:
            memory_score = 10
        else:
            memory_score = 5
    
    # Database optimization score (0-25 points)
    db_score = 0
    if db_optimizations:
        # 5 points for each database type with optimizations
        db_score += min(15, len(db_optimizations) * 5)
        
        # Additional points for high-impact optimizations
        high_impact_count = 0
        for db_type, suggestions in db_optimizations.items():
            for suggestion in suggestions:
                if suggestion.get('metrics', {}).get('estimated_improvement') in ['High', 'Very High']:
                    high_impact_count += 1
        
        db_score += min(10, high_impact_count * 2)
    
    # Network optimization score (0-20 points)
    network_score = min(20, len(network_suggestions) * 4)
    
    # Security optimization score (0-15 points)
    security_score = min(15, len(security_suggestions) * 3)
    
    # Calculate total score
    score = memory_score + db_score + network_score + security_score
    
    return score

# Import datetime for report timestamps
import datetime
