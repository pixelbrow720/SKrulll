
"""
Benchmarking tool for SKrulll components.
"""
import time
import logging
import argparse
import json
import sys
import matplotlib.pyplot as plt
from pathlib import Path

# Add project root to path
sys.path.append('.')

from modules.security.attack_vector_mapper import AttackVectorMapper
from modules.security.entry_point_analyzer import EntryPointAnalyzer
from modules.security.reporting_system import ReportingSystem
from orchestrator.config import load_config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def benchmark_component(component_name, test_function, iterations=5):
    """Run benchmark on a component function"""
    logger.info(f"Benchmarking {component_name}...")
    
    times = []
    for i in range(iterations):
        start_time = time.time()
        test_function()
        end_time = time.time()
        elapsed = end_time - start_time
        times.append(elapsed)
        logger.info(f"  Iteration {i+1}: {elapsed:.4f} seconds")
    
    avg_time = sum(times) / len(times)
    min_time = min(times)
    max_time = max(times)
    
    logger.info(f"  Average: {avg_time:.4f} seconds")
    logger.info(f"  Min: {min_time:.4f} seconds")
    logger.info(f"  Max: {max_time:.4f} seconds")
    
    return {
        'component': component_name,
        'iterations': iterations,
        'times': times,
        'average': avg_time,
        'min': min_time,
        'max': max_time
    }

def load_test_data(data_file):
    """Load test data from JSON file"""
    with open(data_file, 'r') as f:
        return json.load(f)

def plot_results(results, output_file):
    """Generate performance chart"""
    components = [r['component'] for r in results]
    avg_times = [r['average'] for r in results]
    min_times = [r['min'] for r in results]
    max_times = [r['max'] for r in results]
    
    plt.figure(figsize=(10, 6))
    plt.bar(components, avg_times, yerr=[(avg - min) for avg, min in zip(avg_times, min_times)], 
            capsize=5, alpha=0.7, color='blue')
    
    plt.ylabel('Time (seconds)')
    plt.title('Component Performance Benchmark')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    plt.savefig(output_file)
    logger.info(f"Performance chart saved to {output_file}")

def main():
    """Main benchmark runner"""
    parser = argparse.ArgumentParser(description='SKrulll Performance Benchmark')
    parser.add_argument('--iterations', type=int, default=5, help='Number of iterations for each test')
    parser.add_argument('--output', type=str, default='benchmark_results.json', help='Output file for results')
    parser.add_argument('--test-data', type=str, default='tests/test_data.json', help='Test data file')
    parser.add_argument('--chart', type=str, default='benchmark_results.png', help='Output chart file')
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    
    # Load configuration and test data
    config = load_config()
    try:
        test_data = load_test_data(args.test_data)
    except FileNotFoundError:
        logger.error(f"Test data file not found: {args.test_data}")
        return 1
    
    # Prepare components for benchmarking
    attack_mapper = AttackVectorMapper(config['database']['neo4j'])
    entry_analyzer = EntryPointAnalyzer("https://example.com", {})
    reporting = ReportingSystem(config.get('reporting', {}))
    
    # Define test functions
    def test_attack_mapper():
        attack_mapper.consolidate_scan_data(
            test_data.get('nmap_results', {}),
            test_data.get('nuclei_results', {})
        )
    
    def test_entry_analyzer():
        entry_analyzer.generate_access_matrix()
    
    def test_reporting():
        reporting._process_findings(test_data.get('vulnerability_data', {}))
    
    # Run benchmarks
    results = []
    results.append(benchmark_component('Attack Vector Mapper', test_attack_mapper, args.iterations))
    results.append(benchmark_component('Entry Point Analyzer', test_entry_analyzer, args.iterations))
    results.append(benchmark_component('Reporting System', test_reporting, args.iterations))
    
    # Save results
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2)
    logger.info(f"Benchmark results saved to {args.output}")
    
    # Generate chart
    plot_results(results, args.chart)
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
