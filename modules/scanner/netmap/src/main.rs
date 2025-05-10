use network_mapper::{DiscoveryMethod, NetworkMapper, ScanConfig};
use structopt::StructOpt;
use std::str::FromStr;
use std::fs::File;
use std::io::Write;
use std::time::Instant;
use log::{error, info};

#[derive(Debug, StructOpt)]
#[structopt(
    name = "Network Mapper",
    about = "High-speed network discovery and mapping tool"
)]
struct Opt {
    /// Target networks or IPs to scan (CIDR notation supported)
    #[structopt(required = true, min_values = 1)]
    targets: Vec<String>,
    
    /// Scan method [icmp, tcp, arp, combined]
    #[structopt(short, long, default_value = "combined")]
    method: String,
    
    /// Timeout in milliseconds
    #[structopt(short, long, default_value = "1000")]
    timeout: u64,
    
    /// Number of parallel scan threads
    #[structopt(short, long, default_value = "256")]
    parallelism: usize,
    
    /// Skip hostname resolution
    #[structopt(long)]
    no_resolve: bool,
    
    /// Output file (JSON format)
    #[structopt(short, long)]
    output: Option<String>,
    
    /// Enable verbose output
    #[structopt(short, long)]
    verbose: bool,
    
    /// Disable ping check
    #[structopt(long)]
    skip_ping: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    
    // Parse command line arguments
    let opt = Opt::from_args();
    
    if opt.verbose {
        println!("Network Mapper v0.1.0");
        println!("Configuration:");
        println!("  Targets: {:?}", opt.targets);
        println!("  Method: {}", opt.method);
        println!("  Timeout: {} ms", opt.timeout);
        println!("  Parallelism: {}", opt.parallelism);
        println!("  Resolve hostnames: {}", !opt.no_resolve);
        println!("  Skip ping: {}", opt.skip_ping);
        if let Some(ref output) = opt.output {
            println!("  Output file: {}", output);
        }
    }
    
    // Create scan configuration
    let config = ScanConfig {
        targets: opt.targets.clone(),
        timeout_ms: opt.timeout,
        method: match opt.method.to_lowercase().as_str() {
            "icmp" => DiscoveryMethod::IcmpEcho,
            "tcp" => DiscoveryMethod::TcpSyn,
            "arp" => DiscoveryMethod::Arp,
            _ => DiscoveryMethod::Combined,
        },
        parallelism: opt.parallelism,
        resolve_hostnames: !opt.no_resolve,
        skip_ping: opt.skip_ping,
    };
    
    // Create and run the mapper
    let mapper = NetworkMapper::new(config);
    
    info!("Starting network scan...");
    let start_time = Instant::now();
    
    match mapper.scan().await {
        Ok(results) => {
            let elapsed = start_time.elapsed();
            
            info!(
                "Scan completed in {:.2} seconds. Found {} active hosts.",
                elapsed.as_secs_f64(),
                results.len()
            );
            
            if opt.verbose {
                println!("\nActive hosts:");
                for host in &results {
                    println!(
                        "  {} {} {}",
                        host.ip,
                        if let Some(ref hostname) = host.hostname {
                            format!("({})", hostname)
                        } else {
                            String::new()
                        },
                        if let Some(ref mac) = host.mac_address {
                            format!("[{}]", mac)
                        } else {
                            String::new()
                        }
                    );
                }
            }
            
            // Save results to file if requested
            if let Some(output_path) = opt.output {
                let json = serde_json::to_string_pretty(&results)?;
                let mut file = File::create(output_path)?;
                file.write_all(json.as_bytes())?;
                info!("Results saved to file.");
            } else {
                // Otherwise print as JSON to stdout
                let json = serde_json::to_string_pretty(&results)?;
                println!("{}", json);
            }
            
            Ok(())
        },
        Err(e) => {
            error!("Scan error: {}", e);
            Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))
        }
    }
}