"""
Domain Reconnaissance module for the SKrulll Orchestrator.

This module provides functionality for gathering information about a domain,
including WHOIS data, DNS records, and subdomain discovery.
"""
import logging
import socket
import time
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    logger.warning("python-whois not installed, WHOIS functionality will be limited")
    WHOIS_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    logger.warning("dnspython not installed, DNS functionality will be limited")
    DNS_AVAILABLE = False


def get_whois_info(domain: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Get WHOIS information for a domain.
    
    Args:
        domain: Domain name to query
        timeout: Timeout in seconds
        
    Returns:
        Dictionary containing WHOIS information
    """
    result = {
        "domain_name": domain,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "name_servers": [],
        "status": [],
        "emails": [],
        "registrant": None,
        "admin": None,
        "tech": None,
        "error": None
    }
    
    if not WHOIS_AVAILABLE:
        result["error"] = "python-whois not installed"
        return result
    
    try:
        logger.info(f"Performing WHOIS lookup for {domain}")
        domain_whois = whois.whois(domain, timeout=timeout)
        
        # Process the result
        if domain_whois:
            for key in result.keys():
                if key in domain_whois and key != "error":
                    result[key] = domain_whois[key]
            
            # Handle special cases
            if "domain_name" in domain_whois and domain_whois["domain_name"]:
                if isinstance(domain_whois["domain_name"], list):
                    result["domain_name"] = domain_whois["domain_name"][0]
                else:
                    result["domain_name"] = domain_whois["domain_name"]
                    
            # Format dates for consistent output
            for date_field in ['creation_date', 'expiration_date', 'updated_date']:
                if result[date_field]:
                    if isinstance(result[date_field], list):
                        result[date_field] = result[date_field][0].isoformat() if result[date_field][0] else None
                    else:
                        result[date_field] = result[date_field].isoformat() if result[date_field] else None
            
            logger.debug(f"WHOIS lookup successful for {domain}")
        else:
            result["error"] = "No WHOIS information found"
            logger.warning(f"No WHOIS information found for {domain}")
            
    except Exception as e:
        error_msg = str(e)
        result["error"] = error_msg
        logger.error(f"Error during WHOIS lookup for {domain}: {error_msg}", exc_info=True)
    
    return result


def get_dns_records(domain: str, timeout: int = 5) -> Dict[str, List[str]]:
    """
    Get DNS records for a domain.
    
    Args:
        domain: Domain name to query
        timeout: Timeout in seconds
        
    Returns:
        Dictionary containing DNS records by type
    """
    result = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "CNAME": [],
        "SOA": [],
        "error": None
    }
    
    if not DNS_AVAILABLE:
        result["error"] = "dnspython not installed"
        return result
    
    try:
        logger.info(f"Performing DNS lookup for {domain}")
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        
        # Query each record type
        for record_type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
            try:
                answers = resolver.resolve(domain, record_type)
                # Extract the string representation of each answer
                if record_type == "MX":
                    result[record_type] = [f"{answer.preference} {answer.exchange}" for answer in answers]
                elif record_type == "SOA":
                    for answer in answers:
                        result[record_type].append(f"{answer.mname} {answer.rname} {answer.serial} {answer.refresh} {answer.retry} {answer.expire} {answer.minimum}")
                else:
                    result[record_type] = [str(answer) for answer in answers]
            except dns.resolver.NoAnswer:
                # No records of this type
                pass
            except dns.resolver.NXDOMAIN:
                result["error"] = "Domain does not exist"
                break
            except Exception as e:
                logger.warning(f"Error querying {record_type} records for {domain}: {str(e)}")
        
        logger.debug(f"DNS lookup completed for {domain}")
        
    except Exception as e:
        error_msg = str(e)
        result["error"] = error_msg
        logger.error(f"Error during DNS lookup for {domain}: {error_msg}", exc_info=True)
    
    return result


def discover_subdomains(domain: str, wordlist_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Discover subdomains for a domain using a wordlist.
    
    Args:
        domain: Domain name to check
        wordlist_path: Path to a file containing subdomain prefixes
        
    Returns:
        Dictionary containing discovered subdomains
    """
    result = {
        "domain": domain,
        "subdomains": [],
        "error": None
    }
    
    if not DNS_AVAILABLE:
        result["error"] = "dnspython not installed"
        return result
    
    try:
        logger.info(f"Starting subdomain discovery for {domain}")
        
        # Load wordlist
        if wordlist_path:
            try:
                with open(wordlist_path, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
            except Exception as e:
                logger.error(f"Error reading wordlist file: {str(e)}")
                subdomains = get_default_subdomain_list()
        else:
            subdomains = get_default_subdomain_list()
        
        logger.info(f"Loaded {len(subdomains)} potential subdomains to check")
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1
        resolver.lifetime = 1
        
        # Check each potential subdomain
        found_subdomains = []
        for subdomain in subdomains:
            fqdn = f"{subdomain}.{domain}"
            try:
                answers = resolver.resolve(fqdn, "A")
                if answers:
                    ip_addresses = [str(answer) for answer in answers]
                    found_subdomains.append({
                        "name": fqdn,
                        "ip_addresses": ip_addresses
                    })
                    logger.debug(f"Found subdomain: {fqdn}")
            except Exception:
                # Subdomain doesn't resolve
                pass
        
        result["subdomains"] = found_subdomains
        logger.info(f"Discovered {len(found_subdomains)} subdomains for {domain}")
        
    except Exception as e:
        error_msg = str(e)
        result["error"] = error_msg
        logger.error(f"Error during subdomain discovery for {domain}: {error_msg}", exc_info=True)
    
    return result


def get_default_subdomain_list() -> List[str]:
    """
    Get a default list of common subdomain prefixes.
    
    Returns:
        List of common subdomain prefixes
    """
    return [
        "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
        "smtp", "secure", "vpn", "m", "shop", "ftp", "api", "admin", "dev",
        "test", "portal", "ns", "ww1", "host", "support", "mx", "beta",
        "gateway", "intranet", "cloud", "exchange", "app", "news"
    ]


def investigate_domain(domain: str, 
                      perform_whois: bool = True, 
                      perform_dns: bool = True,
                      discover_subdomains: bool = False,
                      whois_timeout: int = 10,
                      dns_timeout: int = 5,
                      subdomain_wordlist: Optional[str] = None) -> Dict[str, Any]:
    """
    Perform comprehensive domain reconnaissance.
    
    Args:
        domain: Domain name to investigate
        perform_whois: Whether to perform WHOIS lookup
        perform_dns: Whether to perform DNS lookups
        discover_subdomains: Whether to discover subdomains
        whois_timeout: Timeout for WHOIS queries
        dns_timeout: Timeout for DNS queries
        subdomain_wordlist: Path to wordlist for subdomain discovery
        
    Returns:
        Dictionary containing all gathered information
    """
    result = {
        "domain": domain,
        "timestamp": time.time(),
        "whois_info": None,
        "dns_records": None,
        "subdomains": None
    }
    
    try:
        logger.info(f"Starting comprehensive domain reconnaissance for {domain}")
        
        # Perform WHOIS lookup if requested
        if perform_whois:
            result["whois_info"] = get_whois_info(domain, timeout=whois_timeout)
            
        # Perform DNS lookups if requested
        if perform_dns:
            result["dns_records"] = get_dns_records(domain, timeout=dns_timeout)
            
        # Discover subdomains if requested
        if discover_subdomains:
            result["subdomains"] = discover_subdomains(domain, wordlist_path=subdomain_wordlist)
            
        logger.info(f"Domain reconnaissance completed for {domain}")
        
    except Exception as e:
        error_msg = str(e)
        result["error"] = error_msg
        logger.error(f"Error during domain reconnaissance for {domain}: {error_msg}", exc_info=True)
    
    return result
