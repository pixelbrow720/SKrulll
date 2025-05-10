//! Network Mapper library for high-speed network discovery
//! 
//! This library provides functionality for scanning network ranges,
//! discovering active hosts, and performing service detection.

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use ipnetwork::IpNetwork;
use log::{debug, error, info, warn};
use pnet::datalink;
use pnet::packet::icmp::echo_request::{EchoRequestPacket, MutableEchoRequestPacket};
use pnet::packet::icmp::{self, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::Packet;
use pnet::transport::{self, TransportChannelType, TransportProtocol};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::time::timeout;

#[cfg(feature = "python")]
use pyo3::prelude::*;

/// Maximum packet size for ICMP
const MAX_PACKET_SIZE: usize = 1500;

/// Default timeout for host discovery
const DEFAULT_TIMEOUT_MS: u64 = 1000;

/// Default number of parallel scanning threads
const DEFAULT_PARALLELISM: usize = 256;

/// Error type for network mapping operations
#[derive(Error, Debug)]
pub enum NetworkMapperError {
    #[error("Failed to parse IP or network: {0}")]
    ParsingError(String),
    
    #[error("Network I/O error: {0}")]
    NetworkError(String),
    
    #[error("Packet crafting error: {0}")]
    PacketError(String),
    
    #[error("Timeout while scanning: {0}")]
    TimeoutError(String),
    
    #[error("Invalid configuration: {0}")]
    ConfigError(String),
    
    #[error("Scanning error: {0}")]
    ScanError(String),
}

/// Result type for network mapping operations
pub type Result<T> = std::result::Result<T, NetworkMapperError>;

/// Host discovery method
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python", pyclass)]
pub enum DiscoveryMethod {
    /// ICMP echo request (ping)
    IcmpEcho,
    
    /// TCP SYN to specified port
    TcpSyn,
    
    /// ARP discovery (only for local networks)
    Arp,
    
    /// Combined method (tries multiple approaches)
    Combined,
}

/// Scan result for a single host
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "python", pyclass)]
pub struct HostResult {
    /// IP address of the host
    pub ip: String,
    
    /// Whether the host is up
    pub is_up: bool,
    
    /// Response time in milliseconds
    pub response_time_ms: Option<u64>,
    
    /// MAC address if available
    pub mac_address: Option<String>,
    
    /// Hostname if resolved
    pub hostname: Option<String>,
    
    /// Method that successfully detected the host
    pub discovery_method: String,
}

/// Configuration for network scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "python", pyclass)]
pub struct ScanConfig {
    /// Network ranges to scan (CIDR notation)
    pub targets: Vec<String>,
    
    /// Timeout in milliseconds
    pub timeout_ms: u64,
    
    /// Discovery method to use
    pub method: DiscoveryMethod,
    
    /// Number of parallel scans
    pub parallelism: usize,
    
    /// Whether to resolve hostnames
    pub resolve_hostnames: bool,
    
    /// Whether to skip ping check before detailed scanning
    pub skip_ping: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            targets: vec![],
            timeout_ms: DEFAULT_TIMEOUT_MS,
            method: DiscoveryMethod::Combined,
            parallelism: DEFAULT_PARALLELISM,
            resolve_hostnames: true,
            skip_ping: false,
        }
    }
}

/// Network mapper for host discovery
pub struct NetworkMapper {
    config: ScanConfig,
    results: Arc<DashMap<String, HostResult>>,
}

impl NetworkMapper {
    /// Create a new network mapper with the given configuration
    pub fn new(config: ScanConfig) -> Self {
        Self {
            config,
            results: Arc::new(DashMap::new()),
        }
    }
    
    /// Run the network scan
    pub async fn scan(&self) -> Result<Vec<HostResult>> {
        info!("Starting network scan with configuration: {:?}", self.config);
        
        // Expand target CIDRs into individual IPs
        let ips = self.expand_targets()?;
        info!("Expanded targets to {} IP addresses", ips.len());
        
        if ips.is_empty() {
            return Err(NetworkMapperError::ConfigError("No valid target IPs found".into()));
        }
        
        match self.config.method {
            DiscoveryMethod::IcmpEcho => {
                self.icmp_scan(&ips).await
            },
            DiscoveryMethod::TcpSyn => {
                // TCP SYN scan defaults to port 80
                self.tcp_scan(&ips, 80).await
            },
            DiscoveryMethod::Arp => {
                self.arp_scan(&ips).await
            },
            DiscoveryMethod::Combined => {
                self.combined_scan(&ips).await
            },
        }
    }
    
    /// Expand target CIDRs into individual IPs
    fn expand_targets(&self) -> Result<Vec<IpAddr>> {
        let mut ips = Vec::new();
        
        for target in &self.config.targets {
            match IpAddr::from_str(target) {
                Ok(ip) => {
                    ips.push(ip);
                },
                Err(_) => {
                    // Try to parse as CIDR
                    match IpNetwork::from_str(target) {
                        Ok(network) => {
                            for ip in network.iter() {
                                ips.push(ip);
                            }
                        },
                        Err(_) => {
                            return Err(NetworkMapperError::ParsingError(
                                format!("Invalid IP or CIDR: {}", target)
                            ));
                        }
                    }
                }
            }
        }
        
        Ok(ips)
    }
    
    /// Perform an ICMP echo scan
    async fn icmp_scan(&self, ips: &[IpAddr]) -> Result<Vec<HostResult>> {
        info!("Starting ICMP echo scan on {} hosts", ips.len());
        
        // Set up ICMP channel
        let (mut tx, mut rx) = match transport::transport_channel(
            MAX_PACKET_SIZE,
            TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp),
        ) {
            Ok((tx, rx)) => (tx, rx),
            Err(e) => {
                return Err(NetworkMapperError::NetworkError(
                    format!("Failed to create ICMP channel: {}", e)
                ));
            }
        };
        
        // Clone Arc for thread safety
        let results = Arc::clone(&self.results);
        let timeout_ms = self.config.timeout_ms;
        let parallelism = self.config.parallelism;
        let resolve_hostnames = self.config.resolve_hostnames;
        
        // Channel for collecting results
        let (sender, mut receiver) = mpsc::channel(parallelism);
        
        // Spawn a task for receiving ICMP responses
        let rx_task = tokio::spawn(async move {
            let mut packet_iter = transport::icmp_packet_iter(&mut rx);
            
            while let Ok((packet, addr)) = packet_iter.next() {
                if packet.get_icmp_type() == icmp::IcmpTypes::EchoReply {
                    // Extract the source IP from the ICMP packet
                    let source_ip = addr.ip().to_string();
                    
                    // Create a host result
                    let mut host_result = HostResult {
                        ip: source_ip.clone(),
                        is_up: true,
                        response_time_ms: Some(0),  // We don't have timing info here
                        mac_address: None,
                        hostname: None,
                        discovery_method: "icmp".to_string(),
                    };
                    
                    // Resolve hostname if requested
                    if resolve_hostnames {
                        if let Ok(hostname) = tokio::task::spawn_blocking(move || {
                            match std::net::lookup_host(format!("{}:0", source_ip)) {
                                Ok(mut addrs) => addrs.next().map(|addr| addr.ip().to_string()),
                                Err(_) => None,
                            }
                        }).await {
                            host_result.hostname = hostname;
                        }
                    }
                    
                    // Store the result
                    results.insert(source_ip, host_result);
                }
            }
        });
        
        // Create a thread pool with fixed size
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(parallelism)
            .build()
            .map_err(|e| NetworkMapperError::ConfigError(format!("Failed to create thread pool: {}", e)))?;
        
        // Process IPs in chunks using the thread pool
        let chunk_size = (ips.len() / parallelism).max(1);
        let chunks: Vec<_> = ips.chunks(chunk_size).collect();
        
        // Create a semaphore to limit concurrent tasks
        let semaphore = Arc::new(tokio::sync::Semaphore::new(parallelism));
        
        // Process chunks in parallel but with controlled concurrency
        let mut handles = Vec::with_capacity(chunks.len());
        
        for chunk in chunks {
            let sender = sender.clone();
            let timeout_ms = timeout_ms;
            let tx = tx.clone();
            let chunk_vec = chunk.to_vec(); // Clone the chunk data
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            
            let handle = tokio::spawn(async move {
                // Process IPs in this chunk
                for &ip in &chunk_vec {
                    // Create an ICMP echo request packet
                    let mut buffer = [0u8; MAX_PACKET_SIZE];
                    
                    if let IpAddr::V4(ipv4_addr) = ip {
                        let mut icmp_packet = MutableEchoRequestPacket::new(&mut buffer[..]).unwrap();
                        icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
                        icmp_packet.set_sequence_number(1);
                        let checksum = icmp::checksum(&icmp_packet.to_immutable());
                        icmp_packet.set_checksum(checksum);
                        
                        // Send the packet
                        match tx.send_to(icmp_packet, IpAddr::V4(ipv4_addr)) {
                            Ok(_) => {},
                            Err(e) => {
                                error!("Failed to send ICMP packet to {}: {}", ip, e);
                            }
                        }
                    }
                    
                    // Wait for timeout_ms before moving to the next IP
                    tokio::time::sleep(Duration::from_millis(timeout_ms)).await;
                }
                
                // Signal completion
                let _ = sender.send(()).await;
                
                // Drop the permit when done to release the semaphore slot
                drop(permit);
            });
            
            handles.push(handle);
        }
        
        // Wait for all scan tasks to complete
        for handle in handles {
            let _ = handle.await;
        }
        
        // Abort the receiving task
        rx_task.abort();
        
        // Collect results
        let host_results: Vec<HostResult> = self.results
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        
        info!("ICMP scan complete. Found {} active hosts", host_results.len());
        
        Ok(host_results)
    }
    
    /// Perform a TCP SYN scan
    async fn tcp_scan(&self, ips: &[IpAddr], port: u16) -> Result<Vec<HostResult>> {
        info!("Starting TCP SYN scan on {} hosts (port {})", ips.len(), port);
        
        // Clone Arc for thread safety
        let results = Arc::clone(&self.results);
        let timeout_ms = self.config.timeout_ms;
        let parallelism = self.config.parallelism;
        let resolve_hostnames = self.config.resolve_hostnames;
        
        // Create a thread pool with fixed size
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(parallelism)
            .build()
            .map_err(|e| NetworkMapperError::ConfigError(format!("Failed to create thread pool: {}", e)))?;
        
        // Create a semaphore to limit concurrent tasks
        let semaphore = Arc::new(tokio::sync::Semaphore::new(parallelism));
        
        // Split IPs into chunks
        let chunk_size = (ips.len() / parallelism).max(1);
        let ip_chunks: Vec<_> = ips.chunks(chunk_size).collect();
        
        // Process chunks in parallel but with controlled concurrency
        let mut handles = Vec::with_capacity(ip_chunks.len());
        
        for chunk in ip_chunks {
            let results = Arc::clone(&results);
            let resolve_hostnames = resolve_hostnames;
            let timeout_ms = timeout_ms;
            let chunk_vec = chunk.to_vec(); // Clone the chunk data
            let port = port;
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            
            let handle = tokio::spawn(async move {
                // Process IPs in this chunk
                for &ip in &chunk_vec {
                    let start = std::time::Instant::now();
                    let socket_addr = std::net::SocketAddr::new(ip, port);
                    
                    // Try to connect with timeout
                    let is_up = match timeout(
                        Duration::from_millis(timeout_ms),
                        tokio::net::TcpStream::connect(socket_addr)
                    ).await {
                        Ok(Ok(_)) => true,
                        _ => false,
                    };
                    
                    if is_up {
                        // Calculate response time
                        let elapsed = start.elapsed().as_millis() as u64;
                        
                        let mut host_result = HostResult {
                            ip: ip.to_string(),
                            is_up: true,
                            response_time_ms: Some(elapsed),
                            mac_address: None,
                            hostname: None,
                            discovery_method: "tcp".to_string(),
                        };
                        
                        // Resolve hostname if requested
                        if resolve_hostnames {
                            let ip_str = ip.to_string();
                            if let Ok(hostname) = tokio::task::spawn_blocking(move || {
                                match std::net::lookup_host(format!("{}:0", ip_str)) {
                                    Ok(mut addrs) => addrs.next().map(|addr| addr.ip().to_string()),
                                    Err(_) => None,
                                }
                            }).await {
                                host_result.hostname = hostname;
                            }
                        }
                        
                        // Store the result
                        results.insert(ip.to_string(), host_result);
                    }
                }
                
                // Drop the permit when done to release the semaphore slot
                drop(permit);
            });
            
            handles.push(handle);
        }
        
        // Wait for all scan tasks to complete
        for handle in handles {
            let _ = handle.await;
        }
        
        // Collect results
        let host_results: Vec<HostResult> = self.results
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        
        info!("TCP scan complete. Found {} active hosts", host_results.len());
        
        Ok(host_results)
    }
    
    /// Perform an ARP scan (only works for local networks)
    async fn arp_scan(&self, ips: &[IpAddr]) -> Result<Vec<HostResult>> {
        info!("Starting ARP scan on {} hosts", ips.len());
        
        // Get the network interfaces
        let interfaces = datalink::interfaces();
        
        // Find the default interface
        let interface = interfaces
            .into_iter()
            .find(|i| i.is_up() && !i.is_loopback() && !i.ips.is_empty())
            .ok_or_else(|| {
                NetworkMapperError::ConfigError("No suitable network interface found".into())
            })?;
        
        // Clone Arc for thread safety
        let results = Arc::clone(&self.results);
        let timeout_ms = self.config.timeout_ms;
        
        // Filter IPs to only include those on the local network
        let local_ips: Vec<_> = ips
            .iter()
            .filter_map(|&ip| {
                if let IpAddr::V4(ipv4) = ip {
                    // Check if IP is in any of the interface's networks
                    for ip_network in &interface.ips {
                        if let ipnetwork::IpNetwork::V4(network) = ip_network {
                            if network.contains(ipv4) {
                                return Some(ipv4);
                            }
                        }
                    }
                }
                None
            })
            .collect();
        
        if local_ips.is_empty() {
            warn!("No IPs in local network range for ARP scan");
            return Ok(Vec::new());
        }
        
        info!("Filtered to {} local IPs for ARP scan", local_ips.len());
        
        // Channel for collecting results
        let (tx, mut rx) = mpsc::channel(100);
        
        // Spawn task for ARP scanning
        tokio::task::spawn_blocking(move || {
            match pnet::datalink::channel(&interface, Default::default()) {
                Ok(pnet::datalink::Channel::Ethernet(mut tx, mut rx)) => {
                    use pnet::datalink::MacAddr;
                    use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
                    use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
                    
                    // Create a runtime for async task execution
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap();
                    
                    // Get interface MAC and IP
                    let source_mac = interface.mac.unwrap_or_else(|| MacAddr::new(0, 0, 0, 0, 0, 0));
                    let source_ip = interface.ips.iter()
                        .find_map(|ip| {
                            if let ipnetwork::IpNetwork::V4(ip) = ip {
                                Some(ip.ip())
                            } else {
                                None
                            }
                        })
                        .unwrap_or_else(|| Ipv4Addr::new(0, 0, 0, 0));
                    
                    // Create a buffer for the packet
                    let mut ethernet_buffer = [0u8; 42];
                    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
                    
                    // Set up the Ethernet frame
                    ethernet_packet.set_destination(MacAddr::broadcast());
                    ethernet_packet.set_source(source_mac);
                    ethernet_packet.set_ethertype(EtherTypes::Arp);
                    
                    // Create the ARP packet
                    let mut arp_buffer = [0u8; 28];
                    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
                    
                    // Set up the ARP request
                    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
                    arp_packet.set_protocol_type(EtherTypes::Ipv4);
                    arp_packet.set_hw_addr_len(6);
                    arp_packet.set_proto_addr_len(4);
                    arp_packet.set_operation(ArpOperations::Request);
                    arp_packet.set_sender_hw_addr(source_mac);
                    arp_packet.set_sender_proto_addr(source_ip);
                    arp_packet.set_target_hw_addr(MacAddr::new(0, 0, 0, 0, 0, 0));
                    
                    // Send ARP requests for each IP
                    for &target_ip in &local_ips {
                        arp_packet.set_target_proto_addr(target_ip);
                        ethernet_packet.set_payload(arp_packet.packet());
                        
                        if let Err(e) = tx.send_to(ethernet_packet.packet(), None) {
                            error!("Failed to send ARP request: {}", e);
                        }
                    }
                    
                    // Set up the result channel
                    let tx_clone = tx.clone();
                    
                    // Spawn a task to listen for ARP replies
                    let listener_handle = std::thread::spawn(move || {
                        // Listen for replies with timeout
                        let start_time = std::time::Instant::now();
                        
                        while start_time.elapsed().as_millis() < timeout_ms as u128 {
                            match rx.next() {
                                Ok(frame) => {
                                    let ethernet = EthernetPacket::new(frame).unwrap();
                                    
                                    if ethernet.get_ethertype() == EtherTypes::Arp {
                                        if let Some(arp) = ArpPacket::new(ethernet.payload()) {
                                            if arp.get_operation() == ArpOperations::Reply {
                                                // Get the IP and MAC address
                                                let ip = arp.get_sender_proto_addr();
                                                let mac = arp.get_sender_hw_addr();
                                                
                                                // Create a host result
                                                let host_result = HostResult {
                                                    ip: ip.to_string(),
                                                    is_up: true,
                                                    response_time_ms: Some(start_time.elapsed().as_millis() as u64),
                                                    mac_address: Some(mac.to_string()),
                                                    hostname: None,
                                                    discovery_method: "arp".to_string(),
                                                };
                                                
                                                // Send the result to the channel
                                                let _ = rt.block_on(tx_clone.send(host_result));
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("Error receiving packet: {}", e);
                                }
                            }
                        }
                    });
                    
                    // Wait for the listener to finish
                    listener_handle.join().unwrap();
                },
                Ok(_) => {
                    error!("Channel type not supported for ARP scanning");
                },
                Err(e) => {
                    error!("Failed to create datalink channel: {}", e);
                }
            }
        });
        
        // Collect results from the channel
        while let Ok(Some(host_result)) = timeout(
            Duration::from_millis(timeout_ms + 1000),
            rx.recv()
        ).await {
            results.insert(host_result.ip.clone(), host_result);
        }
        
        // Collect results
        let host_results: Vec<HostResult> = self.results
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        
        info!("ARP scan complete. Found {} active hosts", host_results.len());
        
        Ok(host_results)
    }
    
    /// Perform a combined scan using multiple methods
    async fn combined_scan(&self, ips: &[IpAddr]) -> Result<Vec<HostResult>> {
        info!("Starting combined network scan on {} hosts", ips.len());
        
        // Clone Arc for thread safety
        let results = Arc::clone(&self.results);
        
        // First try ICMP echo (fastest)
        let mut config = self.config.clone();
        config.method = DiscoveryMethod::IcmpEcho;
        let icmp_mapper = NetworkMapper::new(config);
        let _ = icmp_mapper.scan().await;
        
        // Then try TCP for hosts that didn't respond to ICMP
        let mut remaining_ips = Vec::new();
        for &ip in ips {
            if !results.contains_key(&ip.to_string()) {
                remaining_ips.push(ip);
            }
        }
        
        if !remaining_ips.is_empty() {
            let mut config = self.config.clone();
            config.method = DiscoveryMethod::TcpSyn;
            let tcp_mapper = NetworkMapper::new(config);
            let _ = tcp_mapper.tcp_scan(&remaining_ips, 80).await;
        }
        
        // Finally try ARP for local IPs that haven't responded
        let mut local_ips = Vec::new();
        for &ip in ips {
            if !results.contains_key(&ip.to_string()) {
                if let IpAddr::V4(ipv4) = ip {
                    // Check if IP is likely in a local network
                    if ipv4.is_private() {
                        local_ips.push(ip);
                    }
                }
            }
        }
        
        if !local_ips.is_empty() {
            let mut config = self.config.clone();
            config.method = DiscoveryMethod::Arp;
            let arp_mapper = NetworkMapper::new(config);
            let _ = arp_mapper.arp_scan(&local_ips).await;
        }
        
        // Collect final results
        let host_results: Vec<HostResult> = results
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        
        info!("Combined scan complete. Found {} active hosts", host_results.len());
        
        Ok(host_results)
    }
}

// Python module implementation with PyO3
#[cfg(feature = "python")]
#[pymodule]
fn network_mapper(_py: Python, m: &PyModule) -> PyResult<()> {
    /// Scan network and return active hosts
    #[pyfunction]
    fn scan_network(targets: Vec<String>, timeout_ms: Option<u64>, method: Option<String>) -> PyResult<Vec<HostResult>> {
        // Create scan configuration
        let mut config = ScanConfig::default();
        config.targets = targets;
        
        if let Some(timeout) = timeout_ms {
            config.timeout_ms = timeout;
        }
        
        if let Some(method_str) = method {
            config.method = match method_str.to_lowercase().as_str() {
                "icmp" => DiscoveryMethod::IcmpEcho,
                "tcp" => DiscoveryMethod::TcpSyn,
                "arp" => DiscoveryMethod::Arp,
                _ => DiscoveryMethod::Combined,
            };
        }
        
        // Create and run the mapper
        let mapper = NetworkMapper::new(config);
        
        // Run the scan with a runtime
        let rt = tokio::runtime::Runtime::new().unwrap();
        match rt.block_on(mapper.scan()) {
            Ok(results) => Ok(results),
            Err(e) => {
                // Create a more detailed error message that includes the error type
                let error_type = match e {
                    NetworkMapperError::ParsingError(_) => "ParsingError",
                    NetworkMapperError::NetworkError(_) => "NetworkError",
                    NetworkMapperError::PacketError(_) => "PacketError",
                    NetworkMapperError::TimeoutError(_) => "TimeoutError",
                    NetworkMapperError::ConfigError(_) => "ConfigError",
                    NetworkMapperError::ScanError(_) => "ScanError",
                };
                
                // Format error message to include the error type
                let error_msg = format!("{}: {}", error_type, e.to_string());
                
                // Create a Python exception with the detailed error message
                Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(error_msg))
            },
        }
    }
    
    // Add HostResult class to the module
    m.add_class::<HostResult>()?;
    
    // Add scan_network function to the module
    m.add_function(wrap_pyfunction!(scan_network, m)?)?;
    
    Ok(())
}
