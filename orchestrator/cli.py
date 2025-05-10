"""
Command Line Interface for the SKrulll Orchestrator.

This module defines the CLI commands and structure using Click, organizing
commands into logical groups and providing help documentation.
"""
import logging
import os
import sys
import json
import asyncio
from datetime import datetime
from typing import Optional

import click

from orchestrator.config import load_config
from orchestrator.messaging import MessageBroker
from modules.osint import investigate_domain, get_whois_info, get_dns_records, discover_subdomains
from modules.osint import OsintAggregator, SocialMediaAnalyzer, SearchFootprint
from modules.security import vulnerability_scanner, port_scanner
from modules.security import service_enumerator, network_mapper
from scheduler.task_manager import TaskScheduler

logger = logging.getLogger(__name__)

# Initialize global variables for services
message_broker = None
scheduler = None

@click.group()
@click.version_option(version="0.1.0")
@click.option('--config', '-c', help='Path to configuration file')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--quiet', '-q', is_flag=True, help='Suppress all output except errors')
@click.option('--log-file', '-l', help='Log file path')
@click.pass_context
def cli_app(ctx, config, verbose, quiet, log_file):
    """SKrulll: A comprehensive cybersecurity and OSINT tool orchestrator.
    
    This tool provides a unified interface for various cybersecurity and OSINT tools,
    allowing them to work together seamlessly with centralized configuration and data sharing.
    """
    # Setup context object for passing data between commands
    ctx.ensure_object(dict)
    
    # Load configuration from file if specified
    app_config = load_config(config)
    ctx.obj['config'] = app_config
    
    # Configure logging based on verbosity
    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    elif quiet:
        log_level = logging.ERROR
        
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        logging.getLogger().addHandler(file_handler)
    
    logging.getLogger().setLevel(log_level)
    
    logger.debug("CLI initialized with log level: %s", 
                 logging.getLevelName(log_level))
    
    # Initialize message broker if needed for this command
    global message_broker, scheduler
    if not ctx.invoked_subcommand in ['help', 'version']:
        try:
            message_broker = MessageBroker(config=app_config.get('messaging', {}))
            ctx.obj['message_broker'] = message_broker
            
            # Initialize task scheduler
            scheduler = TaskScheduler(config=app_config.get('scheduler', {}))
            ctx.obj['scheduler'] = scheduler
            
            logger.debug("Core services initialized")
        except Exception as e:
            logger.error(f"Failed to initialize core services: {str(e)}")
            sys.exit(1)


@click.group()
def security_analysis():
    """Security analysis commands."""
    pass


@security_analysis.command()
@click.argument('path')
@click.option('--config', '-c', help='Path to analyzer config')
def analyze_code(path: str, config: Optional[str] = None):
    """Analyze source code for security issues."""
    analyzer = CodeAnalyzer(config)
    issues = analyzer.analyze_python_file(path)
    
    # Print findings
    for issue in issues:
        click.echo(f"{issue.file}:{issue.line} [{issue.severity}] {issue.message}")
        if issue.fix_suggestion:
            click.echo(f"  Fix: {issue.fix_suggestion}")


@security_analysis.command()
@click.option('--config', '-c', help='Path to detector config')
def monitor_leaks(config: Optional[str] = None):
    """Monitor for data leaks."""
    detector = DataLeakDetector(config or {})
    asyncio.run(detector.scan_pastebin())


@security_analysis.command()
@click.argument('files', nargs=-1)
def extract_metadata(files):
    """Extract and analyze file metadata."""
    extractor = MetadataExtractor()
    for file in files:
        try:
            metadata = extractor.extract_all(file)
            click.echo(json.dumps(metadata, indent=2))
        except Exception as e:
            click.echo(f"Error processing {file}: {str(e)}", err=True)


# OSINT Command Group
@cli_app.group()
@click.pass_context
def osint(ctx):
    """Open Source Intelligence (OSINT) tools for reconnaissance and information gathering."""
    pass


@osint.command('domain')
@click.argument('domain')
@click.option('--output', '-o', help='Output file for results')
@click.option('--whois', is_flag=True, help='Perform WHOIS lookup')
@click.option('--dns', is_flag=True, help='Perform DNS enumeration')
@click.option('--subdomains', is_flag=True, help='Discover subdomains')
@click.pass_context
def osint_domain(ctx, domain, output, whois, dns, subdomains):
    """Perform domain reconnaissance and gather information about a target domain."""
    try:
        logger.info(f"Starting domain reconnaissance for {domain}")
        
        # Use the domain_recon module to perform the requested operations
        results = investigate_domain(
            domain, 
            perform_whois=whois,
            perform_dns=dns,
            discover_subdomains=subdomains
        )
        
        # Display results
        click.echo(f"Domain Reconnaissance Results for {domain}:")
        for key, value in results.items():
            click.echo(f"{key}: {value}")
            
        # Save to output file if specified
        if output:
            with open(output, 'w') as f:
                for key, value in results.items():
                    f.write(f"{key}: {value}\n")
            click.echo(f"Results saved to {output}")
            
        logger.info(f"Domain reconnaissance completed for {domain}")
    except Exception as e:
        logger.error(f"Error during domain reconnaissance: {str(e)}", exc_info=True)
        click.echo(f"Error: {str(e)}", err=True)


@osint.command('social')
@click.argument('target')
@click.option('--platforms', '-p', multiple=True, default=['twitter', 'reddit'], 
              help='Social media platforms to analyze (twitter, reddit)')
@click.option('--mode', type=click.Choice(['profile', 'topic']), default='profile',
              help='Analysis mode: profile (username) or topic (search term)')
@click.option('--output', '-o', help='Output file for results')
@click.option('--format', '-f', type=click.Choice(['json', 'pretty', 'summary']), default='summary',
              help='Output format')
@click.pass_context
def osint_social(ctx, target, platforms, mode, output, format):
    """Search for and analyze social media presence of a target username or topic."""
    import json
    import asyncio
    
    try:
        logger.info(f"Starting social media analysis for {target} (mode: {mode})")
        
        # Load configuration from context
        config = ctx.obj.get('config', {})
        
        # Create analyzer
        analyzer = SocialMediaAnalyzer(config)
        
        # Run analysis based on mode
        if mode == 'profile':
            results = asyncio.run(analyzer.analyze_profile(target, list(platforms)))
            title = f"Social Media Profile Analysis for {target}"
        else:
            results = asyncio.run(analyzer.analyze_topic(target, list(platforms)))
            title = f"Social Media Topic Analysis for {target}"
        
        # Display results based on format
        click.echo(title)
        
        if format == 'json':
            formatted_results = json.dumps(results)
            click.echo(formatted_results)
        elif format == 'pretty':
            formatted_results = json.dumps(results, indent=2)
            click.echo(formatted_results)
        else:  # summary
            # Create a simple text summary
            click.echo(f"Platforms analyzed: {', '.join(platforms)}")
            
            # Profile data if available
            if mode == 'profile' and 'profile_data' in results:
                click.echo("\nProfile Information:")
                for platform, profile in results.get('profile_data', {}).items():
                    click.echo(f"  {platform.upper()}:")
                    for key, value in profile.items():
                        if isinstance(value, str) and len(value) > 50:
                            value = value[:50] + "..."
                        click.echo(f"    {key}: {value}")
            
            # Content analysis if available
            if 'content_analysis' in results:
                click.echo("\nContent Analysis:")
                for platform, analysis in results.get('content_analysis', {}).items():
                    click.echo(f"  {platform.upper()}:")
                    sentiment = analysis.get('sentiment', {})
                    total = sum(sentiment.values())
                    if total > 0:
                        pos_pct = (sentiment.get('positive', 0) / total) * 100
                        neg_pct = (sentiment.get('negative', 0) / total) * 100
                        neu_pct = (sentiment.get('neutral', 0) / total) * 100
                        click.echo(f"    Sentiment: {pos_pct:.1f}% Positive, {neg_pct:.1f}% Negative, {neu_pct:.1f}% Neutral")
                    
                    # Top keywords
                    keywords = analysis.get('keywords', {})
                    if keywords:
                        top_keywords = sorted(keywords.items(), key=lambda x: x[1], reverse=True)[:5]
                        click.echo(f"    Top keywords: {', '.join(k for k, v in top_keywords)}")
        
        # Save to output file if specified
        if output:
            if format == 'json':
                with open(output, 'w') as f:
                    f.write(json.dumps(results))
            elif format == 'pretty':
                with open(output, 'w') as f:
                    f.write(json.dumps(results, indent=2))
            else:  # summary - create a simple text summary
                with open(output, 'w') as f:
                    f.write(f"{title}\n")
                    f.write(f"Platforms analyzed: {', '.join(platforms)}\n\n")
                    
                    # Add more summary info here based on the format
                    
            click.echo(f"Results saved to {output}")
            
        logger.info(f"Social media analysis completed for {target}")
    except Exception as e:
        logger.error(f"Error during social media analysis: {str(e)}", exc_info=True)
        click.echo(f"Error: {str(e)}", err=True)


@osint.command('search')
@click.argument('domain')
@click.option('--dork-types', '-d', multiple=True, 
              type=click.Choice(['files', 'exposures', 'subdomains', 'technology', 'credentials']),
              default=['files', 'exposures', 'technology'],
              help='Types of Google dorks to use')
@click.option('--max-results', '-m', type=int, default=20, 
              help='Maximum number of results to return')
@click.option('--classify', '-c', is_flag=True, 
              help='Classify exposed files by risk level')
@click.option('--output', '-o', help='Output file for results')
@click.option('--format', '-f', type=click.Choice(['json', 'pretty']), default='pretty',
              help='Output format')
@click.pass_context
def osint_search(ctx, domain, dork_types, max_results, classify, output, format):
    """Perform search engine footprinting and discover exposed information."""
    import json
    
    try:
        logger.info(f"Starting search engine footprinting for {domain}")
        
        # Load configuration from context
        config = ctx.obj.get('config', {})
        
        # Check for required API keys
        if 'serpapi_key' not in config:
            api_key = os.environ.get('SERPAPI_KEY')
            if api_key:
                config['serpapi_key'] = api_key
            else:
                raise ValueError("SerpAPI key not found in config or environment variables")
        
        # Create footprint analyzer
        analyzer = SearchFootprint(config)
        
        # Run search
        results = analyzer.search_google_dorks(
            domain,
            dork_types=list(dork_types),
            max_results=max_results
        )
        
        # Classify results if requested
        if classify and results["status"] == "success":
            classification = analyzer.classify_exposed_files(results)
            results["classification"] = classification
        
        # Display results based on format
        click.echo(f"Search Engine Footprinting Results for {domain}:")
        
        if format == 'json':
            formatted_results = json.dumps(results)
            click.echo(formatted_results)
        else:  # pretty
            formatted_results = json.dumps(results, indent=2)
            click.echo(formatted_results)
        
        # Save to output file if specified
        if output:
            with open(output, 'w') as f:
                if format == 'json':
                    f.write(json.dumps(results))
                else:
                    f.write(json.dumps(results, indent=2))
            click.echo(f"Results saved to {output}")
            
        logger.info(f"Search engine footprinting completed for {domain}")
    except Exception as e:
        logger.error(f"Error during search engine footprinting: {str(e)}", exc_info=True)
        click.echo(f"Error: {str(e)}", err=True)


# Security Command Group
@cli_app.group()
@click.pass_context
def security(ctx):
    """Security assessment and penetration testing tools."""
    pass


@security.command('portscan')
@click.argument('target')
@click.option('--ports', '-p', help='Port range to scan (e.g., 1-1000 or 22,80,443)')
@click.option('--timeout', '-t', type=float, default=1.0, help='Timeout in seconds for each port')
@click.option('--output', '-o', help='Output file for results')
@click.pass_context
def security_portscan(ctx, target, ports, timeout, output):
    """Perform a port scan on a target host or network."""
    try:
        logger.info(f"Starting port scan on {target}")
        
        # Parse port range
        port_list = []
        if ports:
            if '-' in ports:
                start, end = ports.split('-')
                port_list = list(range(int(start), int(end) + 1))
            elif ',' in ports:
                port_list = [int(p) for p in ports.split(',')]
            else:
                port_list = [int(ports)]
        
        # Use the port_scanner module to perform the scan
        results = port_scanner.scan_ports(target, port_list, timeout)
        
        # Display results
        click.echo(f"Port Scan Results for {target}:")
        for port, is_open in results.items():
            status = "Open" if is_open else "Closed"
            click.echo(f"Port {port}: {status}")
            
        # Save to output file if specified
        if output:
            with open(output, 'w') as f:
                f.write(f"Port Scan Results for {target} - {datetime.now()}\n")
                for port, is_open in results.items():
                    status = "Open" if is_open else "Closed"
                    f.write(f"Port {port}: {status}\n")
            click.echo(f"Results saved to {output}")
            
        logger.info(f"Port scan completed for {target}")
    except Exception as e:
        logger.error(f"Error during port scan: {str(e)}", exc_info=True)
        click.echo(f"Error: {str(e)}", err=True)


@security.command('vulnscan')
@click.argument('target')
@click.option('--level', type=click.Choice(['low', 'medium', 'high']), default='medium', 
              help='Scan intensity level')
@click.option('--output', '-o', help='Output file for results')
@click.pass_context
def security_vulnscan(ctx, target, level, output):
    """Perform a vulnerability scan on a target host or application."""
    try:
        logger.info(f"Starting vulnerability scan on {target} with level {level}")
        
        # Use the vulnerability_scanner module to perform the scan
        results = vulnerability_scanner.scan_vulnerabilities(target, level)
        
        # Display results
        click.echo(f"Vulnerability Scan Results for {target}:")
        if not results:
            click.echo("No vulnerabilities found.")
        else:
            for vuln in results:
                click.echo(f"- {vuln['name']} (Severity: {vuln['severity']})")
                click.echo(f"  Description: {vuln['description']}")
                click.echo(f"  Recommendation: {vuln['recommendation']}")
                click.echo("")
            
        # Save to output file if specified
        if output:
            with open(output, 'w') as f:
                f.write(f"Vulnerability Scan Results for {target} - {datetime.now()}\n")
                if not results:
                    f.write("No vulnerabilities found.\n")
                else:
                    for vuln in results:
                        f.write(f"- {vuln['name']} (Severity: {vuln['severity']})\n")
                        f.write(f"  Description: {vuln['description']}\n")
                        f.write(f"  Recommendation: {vuln['recommendation']}\n\n")
            click.echo(f"Results saved to {output}")
            
        logger.info(f"Vulnerability scan completed for {target}")
    except Exception as e:
        logger.error(f"Error during vulnerability scan: {str(e)}", exc_info=True)
        click.echo(f"Error: {str(e)}", err=True)


# Scheduler Command Group
@cli_app.group()
@click.pass_context
def schedule(ctx):
    """Schedule and manage recurring tasks and jobs."""
    pass


@schedule.command('add')
@click.argument('name')
@click.argument('command')
@click.option('--interval', '-i', type=int, help='Interval in minutes')
@click.option('--cron', '-c', help='Cron expression (e.g., "0 */2 * * *")')
@click.option('--description', '-d', help='Task description')
@click.pass_context
def schedule_add(ctx, name, command, interval, cron, description):
    """Add a new scheduled task."""
    try:
        scheduler = ctx.obj.get('scheduler')
        if not scheduler:
            click.echo("Error: Task scheduler not available", err=True)
            return
        
        if interval and cron:
            click.echo("Error: Cannot specify both interval and cron", err=True)
            return
        
        if interval:
            scheduler.add_interval_task(name, command, interval, description)
            click.echo(f"Task '{name}' scheduled to run every {interval} minutes")
        elif cron:
            scheduler.add_cron_task(name, command, cron, description)
            click.echo(f"Task '{name}' scheduled with cron expression: {cron}")
        else:
            click.echo("Error: Must specify either interval or cron", err=True)
            
    except Exception as e:
        logger.error(f"Error adding scheduled task: {str(e)}", exc_info=True)
        click.echo(f"Error: {str(e)}", err=True)


@schedule.command('list')
@click.pass_context
def schedule_list(ctx):
    """List all scheduled tasks."""
    try:
        scheduler = ctx.obj.get('scheduler')
        if not scheduler:
            click.echo("Error: Task scheduler not available", err=True)
            return
        
        tasks = scheduler.list_tasks()
        if not tasks:
            click.echo("No scheduled tasks found")
            return
            
        click.echo("Scheduled Tasks:")
        for task in tasks:
            schedule_type = "Interval" if task.get('interval') else "Cron"
            schedule_value = task.get('interval', task.get('cron', 'Unknown'))
            click.echo(f"- {task['name']} ({schedule_type}: {schedule_value})")
            if task.get('description'):
                click.echo(f"  Description: {task['description']}")
            click.echo(f"  Command: {task['command']}")
            click.echo("")
            
    except Exception as e:
        logger.error(f"Error listing scheduled tasks: {str(e)}", exc_info=True)
        click.echo(f"Error: {str(e)}", err=True)


@schedule.command('remove')
@click.argument('name')
@click.pass_context
def schedule_remove(ctx, name):
    """Remove a scheduled task."""
    try:
        scheduler = ctx.obj.get('scheduler')
        if not scheduler:
            click.echo("Error: Task scheduler not available", err=True)
            return
        
        if scheduler.remove_task(name):
            click.echo(f"Task '{name}' removed from schedule")
        else:
            click.echo(f"Task '{name}' not found")
            
    except Exception as e:
        logger.error(f"Error removing scheduled task: {str(e)}", exc_info=True)
        click.echo(f"Error: {str(e)}", err=True)


# Web Interface Command
@cli_app.command('webui')
@click.option('--host', default='0.0.0.0', help='Host to bind to')
@click.option('--port', default=5000, help='Port to bind to')
@click.option('--debug', is_flag=True, help='Enable debug mode')
@click.pass_context
def start_webui(ctx, host, port, debug):
    """Start the web-based user interface."""
    try:
        logger.info(f"Starting web UI on {host}:{port}")
        click.echo(f"Starting web UI on http://{host}:{port}")
        
        from web.app import create_app
        
        app = create_app(debug=debug)
        app.run(host=host, port=port, debug=debug)
            
    except Exception as e:
        logger.error(f"Error starting web UI: {str(e)}", exc_info=True)
        click.echo(f"Error: {str(e)}", err=True)


# Database Management Command Group
@cli_app.group()
@click.pass_context
def db(ctx):
    """Database management commands."""
    pass


@db.command('status')
@click.option('--type', '-t', type=click.Choice(['all', 'postgres', 'mongo', 'elasticsearch', 'neo4j']),
              default='all', help='Database type to check')
@click.pass_context
def db_status(ctx, type):
    """Check the status of database connections."""
    try:
        click.echo("Database Connection Status:")
        
        if type in ['all', 'postgres']:
            from orchestrator.db.postgresql_client import check_connection
            postgres_status = "Connected" if check_connection() else "Disconnected"
            click.echo(f"PostgreSQL: {postgres_status}")
            
        if type in ['all', 'mongo']:
            from orchestrator.db.mongodb_client import check_connection
            mongo_status = "Connected" if check_connection() else "Disconnected"
            click.echo(f"MongoDB: {mongo_status}")
            
        if type in ['all', 'elasticsearch']:
            from orchestrator.db.elasticsearch_client import check_connection
            es_status = "Connected" if check_connection() else "Disconnected"
            click.echo(f"Elasticsearch: {es_status}")
            
        if type in ['all', 'neo4j']:
            from orchestrator.db.neo4j_client import check_connection
            neo4j_status = "Connected" if check_connection() else "Disconnected"
            click.echo(f"Neo4j: {neo4j_status}")
            
    except Exception as e:
        logger.error(f"Error checking database status: {str(e)}", exc_info=True)
        click.echo(f"Error: {str(e)}", err=True)


# Messaging System Command Group
@cli_app.group()
@click.pass_context
def messaging(ctx):
    """Messaging system management commands."""
    pass


@messaging.command('status')
@click.pass_context
def messaging_status(ctx):
    """Check the status of the messaging system."""
    try:
        message_broker = ctx.obj.get('message_broker')
        if not message_broker:
            click.echo("Error: Message broker not available", err=True)
            return
        
        status = message_broker.check_status()
        click.echo(f"Messaging System Status: {'Connected' if status else 'Disconnected'}")
            
    except Exception as e:
        logger.error(f"Error checking messaging system status: {str(e)}", exc_info=True)
        click.echo(f"Error: {str(e)}", err=True)


@messaging.command('publish')
@click.argument('topic')
@click.argument('message')
@click.pass_context
def messaging_publish(ctx, topic, message):
    """Publish a message to a topic."""
    try:
        message_broker = ctx.obj.get('message_broker')
        if not message_broker:
            click.echo("Error: Message broker not available", err=True)
            return
        
        message_broker.publish(topic, message)
        click.echo(f"Message published to '{topic}'")
            
    except Exception as e:
        logger.error(f"Error publishing message: {str(e)}", exc_info=True)
        click.echo(f"Error: {str(e)}", err=True)


@security.command('netmap')
@click.argument('targets', nargs=-1, required=True)
@click.option('--method', '-m', type=click.Choice(['icmp', 'tcp', 'arp', 'combined']), 
             default='combined', help='Network discovery method')
@click.option('--timeout', '-t', type=int, default=1000, 
             help='Timeout in milliseconds')
@click.option('--no-resolve', is_flag=True, help='Skip hostname resolution')
@click.option('--visualize', '-v', is_flag=True, help='Generate network visualization')
@click.option('--neo4j', is_flag=True, help='Export results to Neo4j')
@click.option('--output', '-o', help='Output file for results')
@click.pass_context
def security_netmap(ctx, targets, method, timeout, no_resolve, visualize, neo4j, output):
    """Discover and map network hosts and topology."""
    try:
        logger.info(f"Starting network mapping for {targets}")
        
        # Use the network mapper module
        mapper = network_mapper.NetworkMapper(ctx.obj.get('config'))
        
        # Run the scan
        results = mapper.scan_network(
            list(targets),
            method=method,
            timeout_ms=timeout,
            resolve_hostnames=not no_resolve
        )
        
        # Display results
        click.echo(f"Network Mapping Results:")
        click.echo(f"Targets: {', '.join(results['targets'])}")
        click.echo(f"Active Hosts: {results['total_hosts']}")
        
        for host in results['active_hosts']:
            hostname = f" ({host['hostname']})" if host.get('hostname') else ""
            mac = f" [MAC: {host['mac_address']}]" if host.get('mac_address') else ""
            click.echo(f"Host: {host['ip']}{hostname}{mac}")
        
        # Generate visualization if requested
        if visualize:
            try:
                image_path = mapper.visualize_network(results, output)
                click.echo(f"Network visualization saved to: {image_path}")
            except Exception as e:
                logger.error(f"Error generating visualization: {str(e)}")
                click.echo(f"Error generating visualization: {str(e)}", err=True)
        
        # Export to Neo4j if requested
        if neo4j:
            try:
                success = mapper.export_to_neo4j(results)
                if success:
                    click.echo("Results exported to Neo4j successfully")
                else:
                    click.echo("Failed to export results to Neo4j")
            except Exception as e:
                logger.error(f"Error exporting to Neo4j: {str(e)}")
                click.echo(f"Error exporting to Neo4j: {str(e)}", err=True)
        
        # Save to output file if specified
        if output and not visualize:
            with open(output, 'w') as f:
                json.dump(results, f, indent=2)
            click.echo(f"Results saved to {output}")
            
        logger.info(f"Network mapping completed for {targets}")
    except Exception as e:
        logger.error(f"Error during network mapping: {str(e)}", exc_info=True)
        click.echo(f"Error: {str(e)}", err=True)


@security.command('enumservice')
@click.argument('target')
@click.option('--ports', '-p', help='Comma-separated list of ports to scan')
@click.option('--timeout', '-t', type=int, default=2, help='Timeout in seconds')
@click.option('--skip-nmap', is_flag=True, help='Skip using nmap for service detection')
@click.option('--format', '-f', type=click.Choice(['yaml', 'json']), default='yaml',
             help='Output format')
@click.option('--output', '-o', help='Output file for results')
@click.pass_context
def security_enumservice(ctx, target, ports, timeout, skip_nmap, format, output):
    """Enumerate services and detect software versions on a target."""
    try:
        logger.info(f"Starting service enumeration for {target}")
        
        # Parse ports if provided
        port_list = None
        if ports:
            port_list = [int(p.strip()) for p in ports.split(',')]
        
        # Create the service enumerator
        enumerator = service_enumerator.ServiceEnumerator(timeout=timeout)
        
        # Perform the enumeration
        results = enumerator.enumerate_host(
            target,
            ports=port_list,
            use_nmap=not skip_nmap
        )
        
        # Display results
        click.echo(f"Service Enumeration Results for {target}:")
        click.echo(f"Found {len(results['services'])} services on {results['open_ports']} open ports")
        
        # Show services
        for service in results['services']:
            click.echo(f"Port {service['port']} - {service['service']} - {service['version']}")
            if service.get('banner'):
                click.echo(f"  Banner: {service['banner']}")
        
        # Save to output file if specified
        if output:
            if format == 'json':
                with open(output, 'w') as f:
                    json.dump(results, f, indent=2)
            else:  # yaml
                import yaml
                with open(output, 'w') as f:
                    yaml.dump(results, f, default_flow_style=False)
            click.echo(f"Results saved to {output}")
            
        logger.info(f"Service enumeration completed for {target}")
    except Exception as e:
        logger.error(f"Error during service enumeration: {str(e)}", exc_info=True)
        click.echo(f"Error: {str(e)}", err=True)


if __name__ == "__main__":
    cli_app()
