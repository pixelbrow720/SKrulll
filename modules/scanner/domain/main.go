// Domain Scanner
// A fast, concurrent domain scanner for DNS enumeration and port scanning
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// ScanResult represents a domain scan result
type ScanResult struct {
	Domain     string              `json:"domain" bson:"domain"`
	Timestamp  time.Time           `json:"timestamp" bson:"timestamp"`
	IPs        []string            `json:"ips" bson:"ips"`
	Subdomains []string            `json:"subdomains" bson:"subdomains"`
	Records    map[string][]string `json:"dns_records" bson:"dns_records"`
	Ports      map[int]bool        `json:"open_ports" bson:"open_ports"`
	ScanID     string              `json:"scan_id" bson:"scan_id"`
	Complete   bool                `json:"complete" bson:"complete"`
}

// Config represents the scanner configuration
type Config struct {
	Concurrency          int      `json:"concurrency"`
	Timeout              int      `json:"timeout_seconds"`
	PortTimeout          int      `json:"port_timeout_seconds"`
	DNSServers           []string `json:"dns_servers"`
	CommonPorts          []int    `json:"common_ports"`
	WordlistPath         string   `json:"wordlist_path"`
	OutputPath           string   `json:"output_path"`
	MongoDB              string   `json:"mongodb_uri"`
	DBName               string   `json:"db_name"`
	PortScan             bool     `json:"port_scan"`
	BruteforceSubdomains bool     `json:"bruteforce_subdomains"`
	RecursiveScan        bool     `json:"recursive_scan"`
}

// DNSResolverFunc is a function that resolves DNS records
type DNSResolverFunc func(domain string, recordType string) ([]string, error)

var (
	defaultPorts   = []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443}
	dnsRecordTypes = []string{"A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA", "SRV"}

	// Signal handling for graceful shutdown
	sigChan = make(chan os.Signal, 1)

	// MongoDB client
	mongoClient *mongo.Client

	// Progress tracking
	progressLock sync.Mutex
	total        int
	completed    int

	// Resume data
	resumeFile string
	scanID     string
)

func main() {
	// Parse command line flags
	domain := flag.String("domain", "", "Target domain to scan")
	configPath := flag.String("config", "", "Path to config JSON file")
	resume := flag.String("resume", "", "Resume a previous scan ID")
	outputFormat := flag.String("output", "json", "Output format (json, csv)")
	flag.Parse()

	if *domain == "" && *resume == "" {
		fmt.Println("Error: Please provide a domain to scan or a scan ID to resume")
		fmt.Println("Usage: domain_scanner -domain example.com")
		fmt.Println("       domain_scanner -resume <scan_id>")
		os.Exit(1)
	}

	// Load config
	config := loadConfig(*configPath)

	// Create output directory if it doesn't exist
	if config.OutputPath != "" {
		os.MkdirAll(config.OutputPath, 0755)
	}

	// Set up signal handling for graceful shutdown
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go handleSignals()

	// Connect to MongoDB if URI is provided
	if config.MongoDB != "" {
		connectToMongoDB(config.MongoDB)
		defer disconnectMongoDB()
	}

	var result *ScanResult

	// Check if this is a resume operation
	if *resume != "" {
		scanID = *resume
		result = resumeScan(config, scanID)
		if result == nil {
			log.Fatalf("Failed to resume scan with ID %s", scanID)
		}
		*domain = result.Domain
	} else {
		// Generate a new scan ID
		scanID = fmt.Sprintf("%s_%d", *domain, time.Now().Unix())

		// Create a new scan result
		result = &ScanResult{
			Domain:    *domain,
			Timestamp: time.Now(),
			Records:   make(map[string][]string),
			Ports:     make(map[int]bool),
			ScanID:    scanID,
			Complete:  false,
		}
	}

	// Set up the resume file
	if config.OutputPath != "" {
		resumeFile = filepath.Join(config.OutputPath, fmt.Sprintf("%s_resume.json", result.ScanID))
	}

	// Create the DNS resolver
	resolver := createDNSResolver(config)

	// Perform DNS enumeration
	if len(result.Records) == 0 {
		fmt.Println("Performing DNS enumeration...")
		result.Records = enumerateDNS(*domain, resolver)
		saveProgress(result) // Save after DNS enumeration

		// Get IP addresses from A records
		if aRecords, ok := result.Records["A"]; ok {
			result.IPs = aRecords
		}
	} else {
		fmt.Println("Resuming with existing DNS records")
	}

	// Perform subdomain bruteforce if enabled and not already done
	if config.BruteforceSubdomains && len(result.Subdomains) == 0 {
		fmt.Println("Performing subdomain bruteforce...")
		result.Subdomains = bruteforceSubdomains(*domain, config, resolver)
		saveProgress(result) // Save after subdomain bruteforce
	} else if len(result.Subdomains) > 0 {
		fmt.Println("Resuming with existing subdomains")
	}

	// Perform port scanning if enabled and not already done
	if config.PortScan && len(result.Ports) == 0 {
		fmt.Println("Performing port scanning...")
		result.Ports = scanPorts(result.IPs, config)
		saveProgress(result) // Save after port scanning
	} else if len(result.Ports) > 0 {
		fmt.Println("Resuming with existing port scan results")
	}

	// Mark scan as complete
	result.Complete = true
	saveProgress(result)

	// Output final results
	outputResults(result, *outputFormat, config.OutputPath)

	fmt.Printf("Scan completed successfully. Scan ID: %s\n", result.ScanID)
}

// loadConfig loads configuration from a JSON file or returns defaults
func loadConfig(configPath string) Config {
	// Get wordlist path from environment variable or use default
	wordlistPath := os.Getenv("WORDLIST_PATH")
	if wordlistPath == "" {
		wordlistPath = "wordlists/subdomains.txt"
	}

	config := Config{
		Concurrency:          50,
		Timeout:              5,
		PortTimeout:          2,
		DNSServers:           []string{"8.8.8.8", "1.1.1.1"},
		CommonPorts:          defaultPorts,
		WordlistPath:         wordlistPath,
		OutputPath:           "output",
		MongoDB:              os.Getenv("MONGODB_URI"),
		DBName:               "cyberops",
		PortScan:             true,
		BruteforceSubdomains: true,
		RecursiveScan:        false,
	}

	// Override with file config if provided
	if configPath != "" {
		data, err := ioutil.ReadFile(configPath)
		if err != nil {
			log.Printf("Warning: Could not read config file %s: %v", configPath, err)
		} else {
			if err = json.Unmarshal(data, &config); err != nil {
				log.Printf("Warning: Could not parse config file %s: %v", configPath, err)
			}
		}
	}

	return config
}

// createDNSResolver creates a function that resolves DNS records
func createDNSResolver(config Config) DNSResolverFunc {
	resolver := net.Resolver{
		PreferGo: true,
	}

	if len(config.DNSServers) > 0 {
		resolver = net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				// Rotate through DNS servers
				server := config.DNSServers[0]

				d := net.Dialer{
					Timeout: time.Duration(config.Timeout) * time.Second,
				}
				return d.DialContext(ctx, "udp", server+":53")
			},
		}
	}

	return func(domain string, recordType string) ([]string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.Timeout)*time.Second)
		defer cancel()

		var (
			records []string
			err     error
		)

		switch recordType {
		case "A":
			ips, err := resolver.LookupHost(ctx, domain)
			if err != nil {
				return nil, err
			}
			// Filter out IPv6 addresses
			for _, ip := range ips {
				if strings.Contains(ip, ":") {
					continue
				}
				records = append(records, ip)
			}
		case "AAAA":
			ips, err := resolver.LookupHost(ctx, domain)
			if err != nil {
				return nil, err
			}
			// Filter for IPv6 addresses
			for _, ip := range ips {
				if strings.Contains(ip, ":") {
					records = append(records, ip)
				}
			}
		case "MX":
			mxs, err := resolver.LookupMX(ctx, domain)
			if err != nil {
				return nil, err
			}
			for _, mx := range mxs {
				records = append(records, fmt.Sprintf("%s %d", mx.Host, mx.Pref))
			}
		case "TXT":
			txts, err := resolver.LookupTXT(ctx, domain)
			if err != nil {
				return nil, err
			}
			records = txts
		case "CNAME":
			cname, err := resolver.LookupCNAME(ctx, domain)
			if err != nil {
				return nil, err
			}
			if cname != "" {
				records = append(records, cname)
			}
		case "NS":
			nss, err := resolver.LookupNS(ctx, domain)
			if err != nil {
				return nil, err
			}
			for _, ns := range nss {
				records = append(records, ns.Host)
			}
		default:
			err = fmt.Errorf("unsupported record type: %s", recordType)
		}

		return records, err
	}
}

// enumerateDNS performs DNS enumeration for the given domain
func enumerateDNS(domain string, resolver DNSResolverFunc) map[string][]string {
	results := make(map[string][]string)

	fmt.Printf("Enumerating DNS records for %s\n", domain)

	for _, recordType := range dnsRecordTypes {
		records, err := resolver(domain, recordType)
		if err != nil {
			fmt.Printf("Error looking up %s records: %v\n", recordType, err)
			continue
		}

		if len(records) > 0 {
			results[recordType] = records
			fmt.Printf("Found %d %s records\n", len(records), recordType)
		}
	}

	return results
}

// bruteforceSubdomains performs subdomain bruteforce for the given domain
func bruteforceSubdomains(domain string, config Config, resolver DNSResolverFunc) []string {
	var subdomains []string
	var mutex sync.Mutex

	// Check if wordlist exists
	wordlistPath := config.WordlistPath
	if _, err := os.Stat(wordlistPath); os.IsNotExist(err) {
		// Try alternative paths if the primary path doesn't exist
		altPaths := []string{
			"/app/wordlists/subdomains.txt",                                        // Docker container path
			"../wordlists/subdomains.txt",                                          // Relative to module directory
			filepath.Join(os.Getenv("HOME"), ".cyberops/wordlists/subdomains.txt"), // User home directory
		}

		found := false
		for _, altPath := range altPaths {
			if _, err := os.Stat(altPath); !os.IsNotExist(err) {
				log.Printf("Using alternative wordlist at %s", altPath)
				wordlistPath = altPath
				found = true
				break
			}
		}

		if !found {
			log.Printf("Wordlist %s not found, using a minimal built-in list", config.WordlistPath)
			wordlistPath = ""
		}
	}

	// Load wordlist or use a minimal built-in list
	var wordlist []string
	if wordlistPath != "" {
		file, err := os.Open(wordlistPath)
		if err != nil {
			log.Printf("Error opening wordlist: %v", err)
			return subdomains
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			word := strings.TrimSpace(scanner.Text())
			if word != "" && !strings.HasPrefix(word, "#") {
				wordlist = append(wordlist, word)
			}
		}
	} else {
		// Minimal built-in list
		wordlist = []string{
			"www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
			"smtp", "secure", "vpn", "mx", "pop", "api", "dev", "test", "admin",
			"ftp", "ssh", "webdisk", "app", "staging", "m", "mobile", "support",
		}
	}

	total = len(wordlist)
	completed = 0

	fmt.Printf("Starting subdomain bruteforce with %d words\n", total)

	// Create a worker pool
	var wg sync.WaitGroup
	jobChan := make(chan string, config.Concurrency)

	// Start workers
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range jobChan {
				subdomain := fmt.Sprintf("%s.%s", word, domain)
				records, err := resolver(subdomain, "A")
				if err == nil && len(records) > 0 {
					mutex.Lock()
					subdomains = append(subdomains, subdomain)
					mutex.Unlock()
					fmt.Printf("Found subdomain: %s (%s)\n", subdomain, strings.Join(records, ", "))
				}

				// Update progress
				progressLock.Lock()
				completed++
				if completed%100 == 0 {
					fmt.Printf("Progress: %d/%d (%.1f%%)\n", completed, total, float64(completed)/float64(total)*100)
				}
				progressLock.Unlock()
			}
		}()
	}

	// Send jobs to workers
	for _, word := range wordlist {
		select {
		case <-sigChan:
			// Received shutdown signal
			close(jobChan)
			wg.Wait()
			fmt.Println("Subdomain bruteforce interrupted")
			return subdomains
		case jobChan <- word:
			// Job sent successfully
		}
	}

	// Close the job channel and wait for workers to finish
	close(jobChan)
	wg.Wait()

	fmt.Printf("Subdomain bruteforce complete, found %d subdomains\n", len(subdomains))
	return subdomains
}

// scanPorts performs port scanning on the target IPs
func scanPorts(ips []string, config Config) map[int]bool {
	results := make(map[int]bool)
	var mutex sync.Mutex

	if len(ips) == 0 {
		fmt.Println("No IP addresses to scan")
		return results
	}

	// Use common ports or those specified in config
	ports := config.CommonPorts
	if len(ports) == 0 {
		ports = defaultPorts
	}

	total = len(ips) * len(ports)
	completed = 0

	fmt.Printf("Starting port scan on %d IPs with %d ports\n", len(ips), len(ports))

	// Create a worker pool
	var wg sync.WaitGroup
	jobChan := make(chan struct {
		IP   string
		Port int
	}, config.Concurrency)

	// Start workers
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobChan {
				target := fmt.Sprintf("%s:%d", job.IP, job.Port)
				conn, err := net.DialTimeout("tcp", target, time.Duration(config.PortTimeout)*time.Second)
				if err == nil {
					mutex.Lock()
					results[job.Port] = true
					mutex.Unlock()
					conn.Close()
					fmt.Printf("Port %d is open\n", job.Port)
				}

				// Update progress
				progressLock.Lock()
				completed++
				if completed%100 == 0 {
					fmt.Printf("Progress: %d/%d (%.1f%%)\n", completed, total, float64(completed)/float64(total)*100)
				}
				progressLock.Unlock()
			}
		}()
	}

	// Send jobs to workers
	for _, ip := range ips {
		for _, port := range ports {
			select {
			case <-sigChan:
				// Received shutdown signal
				close(jobChan)
				wg.Wait()
				fmt.Println("Port scanning interrupted")
				return results
			case jobChan <- struct {
				IP   string
				Port int
			}{IP: ip, Port: port}:
				// Job sent successfully
			}
		}
	}

	// Close the job channel and wait for workers to finish
	close(jobChan)
	wg.Wait()

	fmt.Printf("Port scan complete, found %d open ports\n", len(results))
	return results
}

// connectToMongoDB connects to the MongoDB server
func connectToMongoDB(uri string) {
	fmt.Println("Connecting to MongoDB...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var err error
	mongoClient, err = mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}

	// Ping the MongoDB server to confirm connection
	err = mongoClient.Ping(ctx, nil)
	if err != nil {
		log.Fatalf("Failed to ping MongoDB: %v", err)
	}

	fmt.Println("Connected to MongoDB")
}

// disconnectMongoDB disconnects from the MongoDB server
func disconnectMongoDB() {
	if mongoClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := mongoClient.Disconnect(ctx); err != nil {
			log.Printf("Error disconnecting from MongoDB: %v", err)
		}
	}
}

// saveProgress saves the current progress to MongoDB and the resume file
func saveProgress(result *ScanResult) {
	// Save to MongoDB if available
	if mongoClient != nil {
		collection := mongoClient.Database("cyberops").Collection("domain_scans")

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Use upsert to update or insert
		filter := bson.M{"scan_id": result.ScanID}
		update := bson.M{"$set": result}
		opts := options.Update().SetUpsert(true)

		_, err := collection.UpdateOne(ctx, filter, update, opts)
		if err != nil {
			log.Printf("Error saving to MongoDB: %v", err)
		}
	}

	// Save to resume file if path is set
	if resumeFile != "" {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			log.Printf("Error marshaling result: %v", err)
			return
		}

		err = ioutil.WriteFile(resumeFile, data, 0644)
		if err != nil {
			log.Printf("Error writing resume file: %v", err)
		}
	}
}

// resumeScan attempts to resume a previous scan
func resumeScan(config Config, scanID string) *ScanResult {
	var result *ScanResult

	// Try to load from MongoDB first
	if mongoClient != nil {
		collection := mongoClient.Database("cyberops").Collection("domain_scans")

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		filter := bson.M{"scan_id": scanID}
		err := collection.FindOne(ctx, filter).Decode(&result)
		if err == nil {
			fmt.Printf("Resumed scan from MongoDB: %s\n", scanID)
			return result
		}

		log.Printf("Could not find scan in MongoDB: %v", err)
	}

	// Try to load from resume file
	if config.OutputPath != "" {
		resumePath := filepath.Join(config.OutputPath, fmt.Sprintf("%s_resume.json", scanID))
		data, err := ioutil.ReadFile(resumePath)
		if err == nil {
			result = &ScanResult{}
			if err = json.Unmarshal(data, result); err == nil {
				fmt.Printf("Resumed scan from file: %s\n", scanID)
				return result
			}

			log.Printf("Error parsing resume file: %v", err)
		}
	}

	return nil
}

// outputResults outputs the scan results in the specified format
func outputResults(result *ScanResult, format string, outputPath string) {
	// Generate output file path
	var outputFile string
	if outputPath != "" {
		outputFile = filepath.Join(outputPath, fmt.Sprintf("%s.%s", result.ScanID, format))
	}

	switch format {
	case "json":
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			log.Printf("Error marshaling results: %v", err)
			return
		}

		if outputFile != "" {
			err = ioutil.WriteFile(outputFile, data, 0644)
			if err != nil {
				log.Printf("Error writing output file: %v", err)
			} else {
				fmt.Printf("Results saved to %s\n", outputFile)
			}
		}

		// Always print a summary to stdout
		fmt.Printf("\nScan Summary for %s:\n", result.Domain)
		fmt.Printf("IPs: %s\n", strings.Join(result.IPs, ", "))
		fmt.Printf("Subdomains: %d found\n", len(result.Subdomains))

		for recordType, records := range result.Records {
			fmt.Printf("%s Records: %d found\n", recordType, len(records))
		}

		var openPorts []string
		for port, isOpen := range result.Ports {
			if isOpen {
				openPorts = append(openPorts, fmt.Sprintf("%d", port))
			}
		}
		fmt.Printf("Open Ports: %s\n", strings.Join(openPorts, ", "))

	case "csv":
		// Implement CSV output if needed
		fmt.Println("CSV output not yet implemented")
	default:
		fmt.Printf("Unsupported output format: %s\n", format)
	}
}

// handleSignals handles OS signals for graceful shutdown
func handleSignals() {
	<-sigChan
	fmt.Println("\nReceived interrupt signal, shutting down...")

	// Clean up here
	if mongoClient != nil {
		disconnectMongoDB()
	}

	// Exit with an appropriate status code
	os.Exit(0)
}
