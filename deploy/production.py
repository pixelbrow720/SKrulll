
#!/usr/bin/env python3
"""
Production deployment script for CyberOps.

This script manages the deployment of CyberOps components to a production environment.
"""
import argparse
import logging
import os
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from typing import List, Dict, Any, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DeploymentManager:
    """Manages the deployment of CyberOps components"""
    
    def __init__(self, config_path: str, env_file: str = '.env.production'):
        """Initialize deployment manager"""
        self.config_path = config_path
        self.env_file = env_file
        self.project_root = Path(__file__).parent.parent
        
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
    
    def check_requirements(self) -> bool:
        """Check if all deployment requirements are met"""
        requirements = [
            ('python', '--version'),
            ('node', '--version'),
            ('docker', '--version'),
            ('docker-compose', '--version')
        ]
        
        all_passed = True
        for cmd, arg in requirements:
            try:
                subprocess.run([cmd, arg], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                logger.info(f"✅ {cmd} is installed")
            except (subprocess.CalledProcessError, FileNotFoundError):
                logger.error(f"❌ {cmd} is not installed or not working properly")
                all_passed = False
        
        return all_passed
    
    def backup_database(self) -> bool:
        """Backup production database before deployment"""
        backup_dir = self.project_root / 'backups'
        backup_dir.mkdir(exist_ok=True)
        
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        
        # Use the DatabaseManager from backup.py for consistent backup functionality
        try:
            from backup import DatabaseManager
            db_manager = DatabaseManager(backup_dir=str(backup_dir), env_file=self.env_file)
            
            logger.info("Starting pre-deployment database backups...")
            
            # Backup all databases
            results = {
                'postgresql': db_manager.backup_postgresql(f"postgres_{timestamp}.sql"),
                'mongodb': db_manager.backup_mongodb(f"mongodb_{timestamp}"),
                'neo4j': db_manager.backup_neo4j(f"neo4j_{timestamp}"),
                'elasticsearch': db_manager.backup_elasticsearch(f"elasticsearch_{timestamp}")
            }
            
            success_count = sum(1 for r in results.values() if r is not None)
            logger.info(f"Database backups completed: {success_count}/{len(results)} successful")
            
            # Create a full backup archive
            archive_path = backup_dir / f"pre_deployment_backup_{timestamp}.tar.gz"
            with tarfile.open(archive_path, "w:gz") as tar:
                for db_name, backup_path in results.items():
                    if backup_path is not None:
                        tar.add(backup_path, arcname=backup_path.name)
            
            logger.info(f"Pre-deployment backup archive created: {archive_path}")
            
            # Return True if at least PostgreSQL backup was successful
            # (as it's the most critical database for this application)
            if results['postgresql'] is not None:
                return True
            else:
                logger.error("Critical database (PostgreSQL) backup failed")
                return False
                
        except ImportError:
            logger.warning("Could not import DatabaseManager from backup.py, falling back to basic backup")
            return self._legacy_backup_database(timestamp, backup_dir)
        except Exception as e:
            logger.error(f"Error during database backup: {e}")
            logger.warning("Falling back to basic backup")
            return self._legacy_backup_database(timestamp, backup_dir)
    
    def _legacy_backup_database(self, timestamp: str, backup_dir: Path) -> bool:
        """Legacy backup method as fallback"""
        success = True
        
        # Backup PostgreSQL
        try:
            pg_backup_file = backup_dir / f"postgres_{timestamp}.sql"
            pg_cmd = [
                'pg_dump',
                f"--host={os.environ.get('PGHOST', 'localhost')}",
                f"--port={os.environ.get('PGPORT', '5432')}",
                f"--username={os.environ.get('PGUSER', 'postgres')}",
                f"--dbname={os.environ.get('PGDATABASE', 'cyberops')}",
                f"--file={pg_backup_file}"
            ]
            
            # Set PGPASSWORD environment variable for the subprocess
            env = os.environ.copy()
            
            subprocess.run(pg_cmd, env=env, check=True)
            logger.info(f"PostgreSQL backup created: {pg_backup_file}")
        except subprocess.CalledProcessError as e:
            logger.error(f"PostgreSQL backup failed: {e}")
            success = False
        
        # Backup MongoDB
        try:
            mongo_backup_dir = backup_dir / f"mongodb_{timestamp}"
            mongo_backup_dir.mkdir(exist_ok=True)
            
            mongo_cmd = [
                'mongodump',
                f"--host={os.environ.get('MONGODB_HOST', 'localhost')}",
                f"--port={os.environ.get('MONGODB_PORT', '27017')}",
                f"--db={os.environ.get('MONGODB_DATABASE', 'cyberops')}"
            ]
            
            # Add authentication if provided
            if os.environ.get('MONGODB_USERNAME'):
                mongo_cmd.extend([
                    f"--username={os.environ.get('MONGODB_USERNAME')}",
                    f"--password={os.environ.get('MONGODB_PASSWORD')}"
                ])
            
            mongo_cmd.append(f"--out={mongo_backup_dir}")
            
            subprocess.run(mongo_cmd, check=True)
            logger.info(f"MongoDB backup created: {mongo_backup_dir}")
        except subprocess.CalledProcessError as e:
            logger.error(f"MongoDB backup failed: {e}")
            # Continue even if MongoDB backup fails
        
        # Backup Neo4j using Cypher export (fallback method)
        try:
            neo4j_backup_dir = backup_dir / f"neo4j_{timestamp}"
            neo4j_backup_dir.mkdir(exist_ok=True)
            export_path = neo4j_backup_dir / "export.cypher"
            
            # Create a temporary file with the Cypher command
            import tempfile
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
                
                # Set NEO4J_PASSWORD environment variable for the subprocess
                env = os.environ.copy()
                
                subprocess.run(cypher_cmd, env=env, check=True)
                logger.info(f"Neo4j backup created using Cypher export: {export_path}")
            finally:
                # Clean up the temporary file
                os.unlink(temp_file_path)
        except subprocess.CalledProcessError as e:
            logger.error(f"Neo4j backup failed: {e}")
            # Continue even if Neo4j backup fails
        
        # Backup Elasticsearch using snapshot API
        try:
            es_backup_dir = backup_dir / f"elasticsearch_{timestamp}"
            es_backup_dir.mkdir(exist_ok=True)
            
            # Create repository for snapshot
            repo_path = es_backup_dir / "repository"
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
            else:
                # Create snapshot
                snapshot_name = f"snapshot_{timestamp}"
                snapshot_response = requests.put(
                    f"{es_url}/_snapshot/cyberops_backup/{snapshot_name}",
                    params={"wait_for_completion": "true"},
                    auth=auth
                )
                
                if snapshot_response.status_code >= 400:
                    logger.error(f"Failed to create Elasticsearch snapshot: {snapshot_response.text}")
                else:
                    logger.info(f"Elasticsearch backup created: {es_backup_dir}")
        except Exception as e:
            logger.error(f"Elasticsearch backup failed: {e}")
            # Continue even if Elasticsearch backup fails
        
        # Create a full backup archive
        try:
            archive_path = backup_dir / f"pre_deployment_backup_{timestamp}.tar.gz"
            with tarfile.open(archive_path, "w:gz") as tar:
                for backup_path in [
                    backup_dir / f"postgres_{timestamp}.sql",
                    backup_dir / f"mongodb_{timestamp}",
                    backup_dir / f"neo4j_{timestamp}",
                    backup_dir / f"elasticsearch_{timestamp}"
                ]:
                    if backup_path.exists():
                        tar.add(backup_path, arcname=backup_path.name)
            
            logger.info(f"Pre-deployment backup archive created: {archive_path}")
        except Exception as e:
            logger.error(f"Failed to create backup archive: {e}")
        
        logger.info("Legacy database backups completed")
        return success
    
    def deploy_services(self) -> bool:
        """Deploy all services using docker-compose"""
        try:
            compose_file = self.project_root / 'templates' / 'docker-compose.yml'
            if not compose_file.exists():
                logger.error(f"Docker Compose file not found: {compose_file}")
                return False
            
            # Pull latest images
            subprocess.run(
                ['docker-compose', '-f', str(compose_file), 'pull'],
                check=True
            )
            logger.info("Docker images pulled successfully")
            
            # Stop and start services
            subprocess.run(
                ['docker-compose', '-f', str(compose_file), 'down'],
                check=True
            )
            
            subprocess.run(
                ['docker-compose', '-f', str(compose_file), 'up', '-d'],
                check=True
            )
            
            logger.info("Services deployed successfully")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Deployment failed: {e}")
            return False
    
    def run_database_migrations(self) -> bool:
        """Run database migrations"""
        try:
            # Run PostgreSQL migrations
            pg_migration_dir = self.project_root / 'migrations' / 'postgresql'
            if pg_migration_dir.exists():
                for migration_file in sorted(pg_migration_dir.glob('*.sql')):
                    logger.info(f"Running migration: {migration_file.name}")
                    pg_cmd = [
                        'psql',
                        f"--host={os.environ.get('PGHOST', 'localhost')}",
                        f"--port={os.environ.get('PGPORT', '5432')}",
                        f"--username={os.environ.get('PGUSER', 'postgres')}",
                        f"--dbname={os.environ.get('PGDATABASE', 'cyberops')}",
                        '-f', str(migration_file)
                    ]
                    
                    # Set PGPASSWORD environment variable for the subprocess
                    env = os.environ.copy()
                    
                    subprocess.run(pg_cmd, env=env, check=True)
            
            # Run Neo4j migrations
            neo4j_migration_dir = self.project_root / 'migrations' / 'neo4j'
            if neo4j_migration_dir.exists():
                for migration_file in sorted(neo4j_migration_dir.glob('*.cypher')):
                    logger.info(f"Running Neo4j migration: {migration_file.name}")
                    
                    # Use a more secure approach for Neo4j credentials
                    # Instead of passing password via command line, use environment variables
                    neo4j_cmd = [
                        'cypher-shell',
                        '-a', os.environ.get('NEO4J_URI', 'bolt://localhost:7687'),
                        '-u', os.environ.get('NEO4J_USERNAME', 'neo4j'),
                        '-f', str(migration_file)
                    ]
                    
                    # Set NEO4J_PASSWORD environment variable for the subprocess
                    env = os.environ.copy()
                    
                    # Run the command
                    subprocess.run(neo4j_cmd, env=env, check=True)
            
            # Run Neo4j optimization script
            neo4j_optimization_script = self.project_root / 'config' / 'neo4j_optimization.cypher'
            if neo4j_optimization_script.exists():
                logger.info(f"Running Neo4j optimization script: {neo4j_optimization_script.name}")
                
                # Use a more secure approach for Neo4j credentials
                neo4j_cmd = [
                    'cypher-shell',
                    '-a', os.environ.get('NEO4J_URI', 'bolt://localhost:7687'),
                    '-u', os.environ.get('NEO4J_USERNAME', 'neo4j'),
                    '-f', str(neo4j_optimization_script)
                ]
                
                # Set NEO4J_PASSWORD environment variable for the subprocess
                env = os.environ.copy()
                
                # Run the command
                subprocess.run(neo4j_cmd, env=env, check=True)
            
            logger.info("Database migrations completed successfully")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Database migration failed: {e}")
            return False
    
    def run_health_checks(self) -> bool:
        """Run health checks on deployed services"""
        services = [
            ('PostgreSQL', f"http://{os.environ.get('PGHOST', 'localhost')}:{os.environ.get('PGPORT', '5432')}", False),
            ('MongoDB', f"http://{os.environ.get('MONGODB_HOST', 'localhost')}:{os.environ.get('MONGODB_PORT', '27017')}", False),
            ('Neo4j', f"http://{os.environ.get('NEO4J_HOST', 'localhost')}:7474", True),
            ('Elasticsearch', f"http://{os.environ.get('ELASTICSEARCH_HOST', 'localhost')}:9200", True),
            ('RabbitMQ', f"http://{os.environ.get('RABBITMQ_HOST', 'localhost')}:15672", True),
            ('Web UI', 'http://localhost:5000', True)
        ]
        
        all_healthy = True
        for name, url, use_http in services:
            if use_http:
                try:
                    import requests
                    response = requests.get(url, timeout=5)
                    if response.status_code < 400:
                        logger.info(f"✅ {name} is healthy")
                    else:
                        logger.warning(f"⚠️ {name} returned status code {response.status_code}")
                        all_healthy = False
                except Exception as e:
                    logger.error(f"❌ {name} health check failed: {e}")
                    all_healthy = False
            else:
                # For database services, we'll just log that we're skipping HTTP checks
                logger.info(f"ℹ️ Skipping HTTP health check for {name} (using connection string: {url})")
        
        return all_healthy
    
    def deploy(self) -> bool:
        """Run the full deployment process"""
        logger.info("Starting CyberOps deployment")
        
        # Check requirements
        if not self.check_requirements():
            logger.error("Deployment requirements not met")
            return False
        
        # Backup database
        if not self.backup_database():
            if input("Database backup failed. Continue anyway? (y/n): ").lower() != 'y':
                return False
        
        # Deploy services
        if not self.deploy_services():
            logger.error("Service deployment failed")
            return False
        
        # Run database migrations
        if not self.run_database_migrations():
            logger.warning("Database migrations failed")
            # Continue anyway, as migrations might not be required for every deployment
        
        # Wait for services to start
        logger.info("Waiting for services to start...")
        time.sleep(30)
        
        # Run health checks
        if not self.run_health_checks():
            logger.warning("Some health checks failed")
            if input("Continue anyway? (y/n): ").lower() != 'y':
                return False
        
        logger.info("Deployment completed successfully!")
        return True

def main():
    """Main entry point for deployment script"""
    parser = argparse.ArgumentParser(description='CyberOps Production Deployment')
    parser.add_argument('--config', type=str, default='config/production.json', help='Path to configuration file')
    parser.add_argument('--env-file', type=str, default='.env.production', help='Path to environment file')
    parser.add_argument('--skip-backup', action='store_true', help='Skip database backup')
    parser.add_argument('--skip-migrations', action='store_true', help='Skip database migrations')
    parser.add_argument('--force', action='store_true', help='Force deployment without prompts')
    args = parser.parse_args()
    
    # Create deployment manager
    deployment = DeploymentManager(args.config, args.env_file)
    
    try:
        result = deployment.deploy()
        return 0 if result else 1
    except KeyboardInterrupt:
        logger.info("Deployment interrupted by user")
        return 1
    except Exception as e:
        logger.exception(f"Deployment failed with error: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
