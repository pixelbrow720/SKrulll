
#!/usr/bin/env python3
"""
Backup and restore script for SKrulll databases.
"""
import argparse
import logging
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
import tarfile
import shutil

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DatabaseManager:
    """Manages backup and restore operations for SKrulll databases"""
    
    def __init__(self, backup_dir: str = 'backups', env_file: str = '.env'):
        """Initialize database manager"""
        self.backup_dir = Path(backup_dir)
        self.env_file = env_file
        self.project_root = Path(__file__).parent.parent
        
        # Create backup directory if it doesn't exist
        self.backup_dir.mkdir(exist_ok=True, parents=True)
        
        # Load environment variables
        self._load_env_file()
    
    def _load_env_file(self) -> None:
        """Load environment variables from .env file"""
        env_path = self.project_root / self.env_file
        if not env_path.exists():
            logger.warning(f"Environment file {self.env_file} not found")
            return
        
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                key, value = line.split('=', 1)
                os.environ[key] = value
        
        logger.info(f"Loaded environment variables from {self.env_file}")
    
    def backup_postgresql(self, output_file: Optional[str] = None) -> Optional[Path]:
        """Backup PostgreSQL database"""
        try:
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            output_path = self.backup_dir / (output_file or f"postgres_{timestamp}.sql")
            
            pg_cmd = [
                'pg_dump',
                f"--host={os.environ.get('PGHOST', 'localhost')}",
                f"--port={os.environ.get('PGPORT', '5432')}",
                f"--username={os.environ.get('PGUSER', 'postgres')}",
                f"--dbname={os.environ.get('PGDATABASE', 'cyberops')}",
                '--format=custom',
                f"--file={output_path}"
            ]
            
            # Set PGPASSWORD environment variable for the subprocess
            env = os.environ.copy()
            
            subprocess.run(pg_cmd, env=env, check=True)
            logger.info(f"PostgreSQL backup created: {output_path}")
            return output_path
        except subprocess.CalledProcessError as e:
            logger.error(f"PostgreSQL backup failed: {e}")
            return None
    
    def backup_mongodb(self, output_dir: Optional[str] = None) -> Optional[Path]:
        """Backup MongoDB database"""
        try:
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            output_path = self.backup_dir / (output_dir or f"mongodb_{timestamp}")
            output_path.mkdir(exist_ok=True)
            
            mongo_cmd = [
                'mongodump',
                f"--host={os.environ.get('MONGODB_HOST', 'localhost')}",
                f"--port={os.environ.get('MONGODB_PORT', '27017')}",
                f"--db={os.environ.get('MONGODB_DATABASE', 'cyberops')}",
                f"--out={output_path}"
            ]
            
            # Add authentication if provided
            if os.environ.get('MONGODB_USERNAME'):
                mongo_cmd.extend([
                    f"--username={os.environ.get('MONGODB_USERNAME')}",
                    f"--password={os.environ.get('MONGODB_PASSWORD')}"
                ])
            
            subprocess.run(mongo_cmd, check=True)
            logger.info(f"MongoDB backup created: {output_path}")
            return output_path
        except subprocess.CalledProcessError as e:
            logger.error(f"MongoDB backup failed: {e}")
            return None
    
    def backup_neo4j(self, output_dir: Optional[str] = None) -> Optional[Path]:
        """
        Backup Neo4j database using admin commands or Cypher export
        
        Note: neo4j-admin backup requires the database to be offline (Enterprise Edition supports online backups).
        This function will attempt to use neo4j-admin backup first, and if that fails, it will fall back to
        using Cypher export via APOC, which works online but may not be as complete as a full backup.
        """
        try:
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            output_path = self.backup_dir / (output_dir or f"neo4j_{timestamp}")
            output_path.mkdir(exist_ok=True)
            
            # Check if we're using Neo4j Enterprise Edition which supports online backups
            is_enterprise = False
            try:
                # Try to determine if we're using Enterprise Edition
                version_cmd = [
                    'cypher-shell',
                    '-a', os.environ.get('NEO4J_URI', 'bolt://localhost:7687'),
                    '-u', os.environ.get('NEO4J_USERNAME', 'neo4j'),
                    '-p', os.environ.get('NEO4J_PASSWORD', ''),
                    'CALL dbms.components() YIELD edition RETURN edition'
                ]
                
                # Use a secure way to pass credentials
                env = os.environ.copy()
                
                result = subprocess.run(
                    version_cmd, 
                    env=env,
                    capture_output=True, 
                    text=True, 
                    check=True
                )
                
                if 'enterprise' in result.stdout.lower():
                    is_enterprise = True
                    logger.info("Detected Neo4j Enterprise Edition, will attempt online backup")
            except Exception as e:
                logger.warning(f"Could not determine Neo4j edition: {e}")
            
            # Use neo4j-admin backup command
            if is_enterprise:
                # Enterprise Edition supports online backup
                neo4j_cmd = [
                    'neo4j-admin', 'backup',
                    f"--backup-dir={output_path}",
                    '--database=neo4j',
                    '--online'  # Enterprise feature for online backup
                ]
            else:
                # Community Edition requires offline backup
                logger.warning("Neo4j Community Edition detected or edition unknown. "
                              "The backup will require the database to be offline. "
                              "Consider using Enterprise Edition for online backups in production.")
                neo4j_cmd = [
                    'neo4j-admin', 'backup',
                    f"--backup-dir={output_path}",
                    '--database=neo4j'
                ]
            
            # Use a secure way to pass credentials
            env = os.environ.copy()
            
            subprocess.run(neo4j_cmd, env=env, check=True)
            logger.info(f"Neo4j backup created: {output_path}")
            return output_path
        except subprocess.CalledProcessError as e:
            logger.error(f"Neo4j backup failed: {e}")
            logger.info("Attempting Neo4j backup using Cypher export as fallback...")
            
            try:
                # Fallback to Cypher export
                export_path = output_path / "export.cypher"
                
                # Use a secure way to handle credentials
                env = os.environ.copy()
                
                # Create a temporary file with the Cypher command
                with tempfile.NamedTemporaryFile(mode='w', suffix='.cypher', delete=False) as temp_file:
                    temp_file.write(f"CALL apoc.export.cypher.all('{export_path}', {{format: 'plain'}});")
                    temp_file_path = temp_file.name
                
                try:
                    # Execute the command using the temporary file
                    cypher_cmd = [
                        'cypher-shell',
                        '-a', os.environ.get('NEO4J_URI', 'bolt://localhost:7687'),
                        '-u', os.environ.get('NEO4J_USERNAME', 'neo4j'),
                        '-f', temp_file_path
                    ]
                    
                    subprocess.run(cypher_cmd, env=env, check=True)
                    logger.info(f"Neo4j backup created using Cypher export: {export_path}")
                    return output_path
                finally:
                    # Clean up the temporary file
                    os.unlink(temp_file_path)
            except subprocess.CalledProcessError as e2:
                logger.error(f"Neo4j Cypher export failed: {e2}")
                return None
    
    def backup_elasticsearch(self, output_dir: Optional[str] = None) -> Optional[Path]:
        """Backup Elasticsearch indices using snapshot API"""
        try:
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            output_path = self.backup_dir / (output_dir or f"elasticsearch_{timestamp}")
            output_path.mkdir(exist_ok=True)
            
            # Create repository for snapshot if it doesn't exist
            repo_path = output_path / "repository"
            repo_path.mkdir(exist_ok=True)
            
            # Use Elasticsearch API to create repository and snapshot
            import requests
            
            # Set up authentication if needed
            auth = None
            if os.environ.get('ELASTICSEARCH_USERNAME'):
                auth = (
                    os.environ.get('ELASTICSEARCH_USERNAME', ''),
                    os.environ.get('ELASTICSEARCH_PASSWORD', '')
                )
            
            es_url = f"http://{os.environ.get('ELASTICSEARCH_HOST', 'localhost:9200')}"
            
            # Register repository
            repo_data = {
                "type": "fs",
                "settings": {
                    "location": str(repo_path)
                }
            }
            
            repo_response = requests.put(
                f"{es_url}/_snapshot/cyberops_backup",
                json=repo_data,
                auth=auth
            )
            
            if repo_response.status_code >= 400:
                logger.error(f"Failed to create Elasticsearch repository: {repo_response.text}")
                return None
            
            # Create snapshot
            snapshot_name = f"snapshot_{timestamp}"
            snapshot_response = requests.put(
                f"{es_url}/_snapshot/cyberops_backup/{snapshot_name}",
                params={"wait_for_completion": "true"},
                auth=auth
            )
            
            if snapshot_response.status_code >= 400:
                logger.error(f"Failed to create Elasticsearch snapshot: {snapshot_response.text}")
                return None
            
            logger.info(f"Elasticsearch backup created: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Elasticsearch backup failed: {e}")
            return None
    
    def backup_all(self) -> Dict[str, Optional[Path]]:
        """Backup all databases"""
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        
        results = {
            'postgresql': self.backup_postgresql(f"postgres_{timestamp}.sql"),
            'mongodb': self.backup_mongodb(f"mongodb_{timestamp}"),
            'neo4j': self.backup_neo4j(f"neo4j_{timestamp}"),
            'elasticsearch': self.backup_elasticsearch(f"elasticsearch_{timestamp}")
        }
        
        success_count = sum(1 for r in results.values() if r is not None)
        logger.info(f"Backup completed: {success_count}/{len(results)} successful")
        
        # Create a full backup archive
        archive_path = self.backup_dir / f"cyberops_backup_{timestamp}.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tar:
            for db_name, backup_path in results.items():
                if backup_path is not None:
                    tar.add(backup_path, arcname=backup_path.name)
        
        logger.info(f"Full backup archive created: {archive_path}")
        return results
    
    def restore_postgresql(self, backup_file: str) -> bool:
        """Restore PostgreSQL database from backup"""
        try:
            backup_path = Path(backup_file)
            if not backup_path.exists():
                logger.error(f"PostgreSQL backup file not found: {backup_file}")
                return False
            
            # Drop and recreate database
            drop_cmd = [
                'psql',
                f"--host={os.environ.get('PGHOST', 'localhost')}",
                f"--port={os.environ.get('PGPORT', '5432')}",
                f"--username={os.environ.get('PGUSER', 'postgres')}",
                '--dbname=postgres',
                '-c', f"DROP DATABASE IF EXISTS {os.environ.get('PGDATABASE', 'cyberops')}"
            ]
            
            create_cmd = [
                'psql',
                f"--host={os.environ.get('PGHOST', 'localhost')}",
                f"--port={os.environ.get('PGPORT', '5432')}",
                f"--username={os.environ.get('PGUSER', 'postgres')}",
                '--dbname=postgres',
                '-c', f"CREATE DATABASE {os.environ.get('PGDATABASE', 'cyberops')}"
            ]
            
            # Set PGPASSWORD environment variable for the subprocesses
            env = os.environ.copy()
            
            subprocess.run(drop_cmd, env=env, check=True)
            subprocess.run(create_cmd, env=env, check=True)
            
            # Restore from backup
            restore_cmd = [
                'pg_restore',
                f"--host={os.environ.get('PGHOST', 'localhost')}",
                f"--port={os.environ.get('PGPORT', '5432')}",
                f"--username={os.environ.get('PGUSER', 'postgres')}",
                f"--dbname={os.environ.get('PGDATABASE', 'cyberops')}",
                '--no-owner',
                '--no-privileges',
                str(backup_path)
            ]
            
            subprocess.run(restore_cmd, env=env, check=True)
            logger.info(f"PostgreSQL restored from: {backup_file}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"PostgreSQL restore failed: {e}")
            return False
    
    def restore_mongodb(self, backup_dir: str) -> bool:
        """Restore MongoDB database from backup"""
        try:
            backup_path = Path(backup_dir)
            if not backup_path.exists() or not backup_path.is_dir():
                logger.error(f"MongoDB backup directory not found: {backup_dir}")
                return False
            
            # Restore from backup
            mongo_cmd = [
                'mongorestore',
                f"--host={os.environ.get('MONGODB_HOST', 'localhost')}",
                f"--port={os.environ.get('MONGODB_PORT', '27017')}",
                f"--db={os.environ.get('MONGODB_DATABASE', 'cyberops')}",
                '--drop',
                backup_path
            ]
            
            # Add authentication if provided
            if os.environ.get('MONGODB_USERNAME'):
                mongo_cmd.extend([
                    f"--username={os.environ.get('MONGODB_USERNAME')}",
                    f"--password={os.environ.get('MONGODB_PASSWORD')}"
                ])
            
            subprocess.run(mongo_cmd, check=True)
            logger.info(f"MongoDB restored from: {backup_dir}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"MongoDB restore failed: {e}")
            return False
    
    def restore_neo4j(self, backup_dir: str) -> bool:
        """Restore Neo4j database from backup"""
        try:
            backup_path = Path(backup_dir)
            if not backup_path.exists() or not backup_path.is_dir():
                logger.error(f"Neo4j backup directory not found: {backup_dir}")
                return False
            
            # Use neo4j-admin restore command
            neo4j_cmd = [
                'neo4j-admin', 'restore',
                f"--from={backup_path}",
                '--database=neo4j',
                '--force'
            ]
            
            subprocess.run(neo4j_cmd, check=True)
            logger.info(f"Neo4j restored from: {backup_dir}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Neo4j restore failed: {e}")
            
            # Check for Cypher export fallback
            export_path = backup_path / "export.cypher"
            if export_path.exists():
                logger.info("Attempting Neo4j restore using Cypher export...")
                try:
                    # Clear database first
                    clear_cmd = [
                        'cypher-shell',
                        '-a', os.environ.get('NEO4J_URI', 'bolt://localhost:7687'),
                        '-u', os.environ.get('NEO4J_USERNAME', 'neo4j'),
                        '-p', os.environ.get('NEO4J_PASSWORD', ''),
                        'MATCH (n) DETACH DELETE n'
                    ]
                    
                    # Then import from Cypher file
                    import_cmd = [
                        'cypher-shell',
                        '-a', os.environ.get('NEO4J_URI', 'bolt://localhost:7687'),
                        '-u', os.environ.get('NEO4J_USERNAME', 'neo4j'),
                        '-p', os.environ.get('NEO4J_PASSWORD', ''),
                        '-f', str(export_path)
                    ]
                    
                    subprocess.run(clear_cmd, check=True)
                    subprocess.run(import_cmd, check=True)
                    logger.info(f"Neo4j restored from Cypher export: {export_path}")
                    return True
                except subprocess.CalledProcessError as e2:
                    logger.error(f"Neo4j Cypher import failed: {e2}")
                    return False
            
            return False
    
    def restore_elasticsearch(self, backup_dir: str) -> bool:
        """Restore Elasticsearch indices from snapshot"""
        try:
            backup_path = Path(backup_dir)
            if not backup_path.exists() or not backup_path.is_dir():
                logger.error(f"Elasticsearch backup directory not found: {backup_dir}")
                return False
            
            # Use Elasticsearch API to restore from snapshot
            import requests
            
            # Set up authentication if needed
            auth = None
            if os.environ.get('ELASTICSEARCH_USERNAME'):
                auth = (
                    os.environ.get('ELASTICSEARCH_USERNAME', ''),
                    os.environ.get('ELASTICSEARCH_PASSWORD', '')
                )
            
            es_url = f"http://{os.environ.get('ELASTICSEARCH_HOST', 'localhost:9200')}"
            
            # Register repository if not already registered
            repo_data = {
                "type": "fs",
                "settings": {
                    "location": str(backup_path / "repository")
                }
            }
            
            repo_response = requests.put(
                f"{es_url}/_snapshot/cyberops_backup",
                json=repo_data,
                auth=auth
            )
            
            if repo_response.status_code >= 400 and repo_response.status_code != 400:
                logger.error(f"Failed to create Elasticsearch repository: {repo_response.text}")
                return False
            
            # Get latest snapshot
            snapshots_response = requests.get(
                f"{es_url}/_snapshot/cyberops_backup/_all",
                auth=auth
            )
            
            if snapshots_response.status_code >= 400:
                logger.error(f"Failed to get Elasticsearch snapshots: {snapshots_response.text}")
                return False
            
            snapshots = snapshots_response.json()
            if 'snapshots' not in snapshots or not snapshots['snapshots']:
                logger.error("No Elasticsearch snapshots found in repository")
                return False
            
            latest_snapshot = snapshots['snapshots'][0]['snapshot']
            
            # Close all indices
            close_response = requests.post(
                f"{es_url}/_all/_close",
                auth=auth
            )
            
            # Restore from snapshot
            restore_response = requests.post(
                f"{es_url}/_snapshot/cyberops_backup/{latest_snapshot}/_restore",
                params={"wait_for_completion": "true"},
                auth=auth
            )
            
            if restore_response.status_code >= 400:
                logger.error(f"Failed to restore Elasticsearch snapshot: {restore_response.text}")
                return False
            
            logger.info(f"Elasticsearch restored from: {backup_dir}")
            return True
        except Exception as e:
            logger.error(f"Elasticsearch restore failed: {e}")
            return False
    
    def restore_all(self, backup_archive: str) -> Dict[str, bool]:
        """Restore all databases from a full backup archive"""
        try:
            archive_path = Path(backup_archive)
            if not archive_path.exists():
                logger.error(f"Backup archive not found: {backup_archive}")
                return {'success': False}
            
            # Create a temporary directory for extraction
            import tempfile
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Extract the archive
                with tarfile.open(archive_path, "r:gz") as tar:
                    tar.extractall(path=temp_path)
                
                # Find the extracted backup files/directories
                postgres_backups = list(temp_path.glob("postgres_*.sql"))
                mongodb_backups = list(temp_path.glob("mongodb_*"))
                neo4j_backups = list(temp_path.glob("neo4j_*"))
                elasticsearch_backups = list(temp_path.glob("elasticsearch_*"))
                
                results = {
                    'postgresql': False,
                    'mongodb': False,
                    'neo4j': False,
                    'elasticsearch': False
                }
                
                # Restore each database if backup exists
                if postgres_backups:
                    results['postgresql'] = self.restore_postgresql(postgres_backups[0])
                
                if mongodb_backups:
                    results['mongodb'] = self.restore_mongodb(mongodb_backups[0])
                
                if neo4j_backups:
                    results['neo4j'] = self.restore_neo4j(neo4j_backups[0])
                
                if elasticsearch_backups:
                    results['elasticsearch'] = self.restore_elasticsearch(elasticsearch_backups[0])
                
                success_count = sum(1 for r in results.values() if r)
                logger.info(f"Restore completed: {success_count}/{len(results)} successful")
                results['success'] = success_count == len(results)
                
                return results
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return {'success': False}

def main():
    """Main entry point for backup/restore script"""
    parser = argparse.ArgumentParser(description='SKrulll Database Backup and Restore')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Backup command
    backup_parser = subparsers.add_parser('backup', help='Backup databases')
    backup_parser.add_argument('--output-dir', type=str, default='backups', help='Output directory for backups')
    backup_parser.add_argument('--env-file', type=str, default='.env', help='Path to environment file')
    backup_parser.add_argument('--postgres-only', action='store_true', help='Backup only PostgreSQL')
    backup_parser.add_argument('--mongodb-only', action='store_true', help='Backup only MongoDB')
    backup_parser.add_argument('--neo4j-only', action='store_true', help='Backup only Neo4j')
    backup_parser.add_argument('--elastic-only', action='store_true', help='Backup only Elasticsearch')
    
    # Restore command
    restore_parser = subparsers.add_parser('restore', help='Restore databases')
    restore_parser.add_argument('--backup-file', type=str, required=True, help='Backup file or archive to restore from')
    restore_parser.add_argument('--env-file', type=str, default='.env', help='Path to environment file')
    restore_parser.add_argument('--postgres-only', action='store_true', help='Restore only PostgreSQL')
    restore_parser.add_argument('--mongodb-only', action='store_true', help='Restore only MongoDB')
    restore_parser.add_argument('--neo4j-only', action='store_true', help='Restore only Neo4j')
    restore_parser.add_argument('--elastic-only', action='store_true', help='Restore only Elasticsearch')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Create database manager
    db_manager = DatabaseManager(
        backup_dir=args.output_dir if args.command == 'backup' else 'backups',
        env_file=args.env_file
    )
    
    if args.command == 'backup':
        # Determine which databases to backup
        only_flags = [
            args.postgres_only,
            args.mongodb_only,
            args.neo4j_only,
            args.elastic_only
        ]
        
        # If no specific database is requested, backup all
        if not any(only_flags):
            results = db_manager.backup_all()
            return 0 if any(results.values()) else 1
        
        # Otherwise, backup only the requested databases
        results = {}
        if args.postgres_only:
            results['postgresql'] = db_manager.backup_postgresql()
        if args.mongodb_only:
            results['mongodb'] = db_manager.backup_mongodb()
        if args.neo4j_only:
            results['neo4j'] = db_manager.backup_neo4j()
        if args.elastic_only:
            results['elasticsearch'] = db_manager.backup_elasticsearch()
        
        return 0 if any(results.values()) else 1
    
    elif args.command == 'restore':
        # Check if the backup file is an archive
        is_archive = args.backup_file.endswith('.tar.gz') or args.backup_file.endswith('.tgz')
        
        # Determine which databases to restore
        only_flags = [
            args.postgres_only,
            args.mongodb_only,
            args.neo4j_only,
            args.elastic_only
        ]
        
        # If it's an archive and no specific database is requested, restore all
        if is_archive and not any(only_flags):
            results = db_manager.restore_all(args.backup_file)
            return 0 if results.get('success', False) else 1
        
        # Otherwise, restore only the requested databases or a specific backup file/directory
        success = False
        
        if is_archive:
            logger.error("Cannot restore specific databases from an archive when using --*-only flags")
            logger.error("Please extract the archive manually and specify individual backup files/directories")
            return 1
        
        if args.postgres_only:
            success = db_manager.restore_postgresql(args.backup_file)
        elif args.mongodb_only:
            success = db_manager.restore_mongodb(args.backup_file)
        elif args.neo4j_only:
            success = db_manager.restore_neo4j(args.backup_file)
        elif args.elastic_only:
            success = db_manager.restore_elasticsearch(args.backup_file)
        else:
            # Try to determine the database type from the backup file/directory
            backup_path = Path(args.backup_file)
            
            if backup_path.is_file() and backup_path.name.startswith("postgres_"):
                success = db_manager.restore_postgresql(args.backup_file)
            elif backup_path.is_dir() and backup_path.name.startswith("mongodb_"):
                success = db_manager.restore_mongodb(args.backup_file)
            elif backup_path.is_dir() and backup_path.name.startswith("neo4j_"):
                success = db_manager.restore_neo4j(args.backup_file)
            elif backup_path.is_dir() and backup_path.name.startswith("elasticsearch_"):
                success = db_manager.restore_elasticsearch(args.backup_file)
            else:
                logger.error(f"Could not determine database type from backup file/directory: {args.backup_file}")
                return 1
        
        return 0 if success else 1

if __name__ == '__main__':
    sys.exit(main())
