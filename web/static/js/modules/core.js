/**
 * Core module for SKrulll Dashboard
 * Contains core functionality and initialization
 */

// Global variables
let refreshInterval;
let socket; // WebSocket connection for real-time updates

/**
 * Initialize WebSocket connection for real-time updates
 */
function initializeWebSocket() {
  // Check if WebSocket is supported
  if ('WebSocket' in window) {
    try {
      // Try to connect to WebSocket server (if available)
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws`;
      
      socket = new WebSocket(wsUrl);
      
      socket.onopen = function() {
        console.log('WebSocket connection established');
        ui.showToast('Real-time updates enabled', 'info');
      };
      
      socket.onmessage = function(event) {
        try {
          const data = JSON.parse(event.data);
          
          // Handle different types of real-time updates
          switch (data.type) {
            case 'system_status':
              updateSystemStatus(data.data);
              break;
              
            case 'task_update':
              tasks.updateTaskStatus(data.data);
              break;
              
            case 'scan_result':
              updateScanResults(data.data);
              break;
              
            default:
              console.log('Unknown message type:', data.type);
          }
        } catch (error) {
          console.error('Error processing WebSocket message:', error);
        }
      };
      
      socket.onclose = function() {
        console.log('WebSocket connection closed');
        // Try to reconnect after 5 seconds
        setTimeout(initializeWebSocket, 5000);
      };
      
      socket.onerror = function(error) {
        console.error('WebSocket error:', error);
      };
    } catch (error) {
      console.error('Error initializing WebSocket:', error);
    }
  }
}

/**
 * Check system status via API calls
 */
function checkSystemStatus() {
  // Check database status
  api.fetchWithAuth('/api/db/status')
    .then(response => response.json())
    .then(data => {
      const dbStatus = document.getElementById('db-status');
      if (!dbStatus) return;
      
      // Clear previous classes
      dbStatus.classList.remove('connected', 'disconnected', 'warning');
      
      if (data.status === 'success' && data.data.status === 'connected') {
        dbStatus.textContent = 'Connected';
        dbStatus.classList.add('connected');
        
        // Add details as tooltip
        let details = '';
        for (const [db, status] of Object.entries(data.data)) {
          if (db !== 'status') {
            details += `${db}: ${status ? 'Connected' : 'Disconnected'}\n`;
          }
        }
        dbStatus.setAttribute('title', details);
        dbStatus.setAttribute('data-bs-toggle', 'tooltip');
        dbStatus.setAttribute('data-bs-placement', 'bottom');
      } else {
        dbStatus.textContent = 'Disconnected';
        dbStatus.classList.add('disconnected');
      }
    })
    .catch(error => {
      console.error('Error checking DB status:', error);
      const dbStatus = document.getElementById('db-status');
      if (dbStatus) {
        dbStatus.textContent = 'Error';
        dbStatus.classList.remove('connected', 'warning');
        dbStatus.classList.add('disconnected');
      }
    });
  
  // Check messaging status
  api.fetchWithAuth('/api/messaging/status')
    .then(response => response.json())
    .then(data => {
      const msgStatus = document.getElementById('messaging-status');
      if (!msgStatus) return;
      
      // Clear previous classes
      msgStatus.classList.remove('connected', 'disconnected', 'warning');
      
      if (data.status === 'success' && data.data.status === 'connected') {
        msgStatus.textContent = 'Connected';
        msgStatus.classList.add('connected');
        msgStatus.setAttribute('title', `Broker: ${data.data.broker_type}`);
        msgStatus.setAttribute('data-bs-toggle', 'tooltip');
        msgStatus.setAttribute('data-bs-placement', 'bottom');
      } else {
        msgStatus.textContent = 'Disconnected';
        msgStatus.classList.add('disconnected');
      }
    })
    .catch(error => {
      console.error('Error checking messaging status:', error);
      const msgStatus = document.getElementById('messaging-status');
      if (msgStatus) {
        msgStatus.textContent = 'Error';
        msgStatus.classList.remove('connected', 'warning');
        msgStatus.classList.add('disconnected');
      }
    });
    
  // Check system info
  api.fetchWithAuth('/api/system/info')
    .then(response => response.json())
    .then(data => {
      const systemLoad = document.getElementById('system-load');
      if (!systemLoad) return;
      
      // Clear previous classes
      systemLoad.classList.remove('connected', 'disconnected', 'warning');
      
      if (data.status === 'success') {
        const cpuPercent = data.data.cpu_percent;
        const memPercent = data.data.memory.percent;
        
        // Determine load status
        let status = 'Normal';
        let statusClass = 'connected';
        
        if (cpuPercent > 80 || memPercent > 80) {
          status = 'High';
          statusClass = 'warning';
        } else if (cpuPercent > 90 || memPercent > 90) {
          status = 'Critical';
          statusClass = 'disconnected';
        }
        
        systemLoad.textContent = status;
        systemLoad.classList.add(statusClass);
        
        // Add details as tooltip
        const details = `CPU: ${cpuPercent}%\nMemory: ${memPercent}%\nOS: ${data.data.os}`;
        systemLoad.setAttribute('title', details);
        systemLoad.setAttribute('data-bs-toggle', 'tooltip');
        systemLoad.setAttribute('data-bs-placement', 'bottom');
        
        // Initialize tooltip if Bootstrap is available
        if (typeof bootstrap !== 'undefined') {
          new bootstrap.Tooltip(systemLoad);
        }
        
        // Update system info chart if exists
        updateSystemChart(cpuPercent, memPercent);
      } else {
        systemLoad.textContent = 'Unknown';
        systemLoad.classList.add('warning');
      }
    })
    .catch(error => {
      console.error('Error checking system info:', error);
      const systemLoad = document.getElementById('system-load');
      if (systemLoad) {
        systemLoad.textContent = 'Error';
        systemLoad.classList.remove('connected', 'warning');
        systemLoad.classList.add('disconnected');
      }
    });
}

/**
 * Update system info chart
 */
function updateSystemChart(cpu, memory) {
  const chartCanvas = document.getElementById('system-chart');
  if (!chartCanvas) return;
  
  // Check if Chart.js is available
  if (typeof Chart === 'undefined') return;
  
  // Check if chart already exists
  let chartInstance = Chart.getChart(chartCanvas);
  
  if (chartInstance) {
    // Update existing chart
    chartInstance.data.datasets[0].data = [cpu, memory];
    chartInstance.update();
  } else {
    // Create new chart
    chartInstance = new Chart(chartCanvas, {
      type: 'doughnut',
      data: {
        labels: ['CPU', 'Memory'],
        datasets: [{
          data: [cpu, memory],
          backgroundColor: [
            'rgba(59, 130, 246, 0.7)',
            'rgba(139, 92, 246, 0.7)'
          ],
          borderColor: [
            'rgba(59, 130, 246, 1)',
            'rgba(139, 92, 246, 1)'
          ],
          borderWidth: 1
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              color: '#94a3b8'
            }
          },
          tooltip: {
            callbacks: {
              label: function(context) {
                return `${context.label}: ${context.raw}%`;
              }
            }
          }
        }
      }
    });
  }
}

/**
 * Update system status from WebSocket data
 */
function updateSystemStatus(data) {
  // Update database status
  if (data.database) {
    const dbStatus = document.getElementById('db-status');
    if (dbStatus) {
      dbStatus.textContent = data.database.status;
      dbStatus.className = `status-indicator ${data.database.status === 'connected' ? 'connected' : 'disconnected'}`;
    }
  }
  
  // Update messaging status
  if (data.messaging) {
    const msgStatus = document.getElementById('messaging-status');
    if (msgStatus) {
      msgStatus.textContent = data.messaging.status;
      msgStatus.className = `status-indicator ${data.messaging.status === 'connected' ? 'connected' : 'disconnected'}`;
    }
  }
  
  // Update system load
  if (data.system) {
    const systemLoad = document.getElementById('system-load');
    if (systemLoad) {
      let status = 'Normal';
      let statusClass = 'connected';
      
      if (data.system.cpu_percent > 80 || data.system.memory.percent > 80) {
        status = 'High';
        statusClass = 'warning';
      } else if (data.system.cpu_percent > 90 || data.system.memory.percent > 90) {
        status = 'Critical';
        statusClass = 'disconnected';
      }
      
      systemLoad.textContent = status;
      systemLoad.className = `status-indicator ${statusClass}`;
      
      // Update chart if exists
      updateSystemChart(data.system.cpu_percent, data.system.memory.percent);
    }
  }
}

/**
 * Update scan results from WebSocket data
 */
function updateScanResults(data) {
  const resultsOutput = document.getElementById('results-output');
  if (!resultsOutput) return;
  
  // Format results
  let formattedResults = '';
  
  if (data.type === 'domain_recon') {
    formattedResults = formatDomainReconResults(data.results);
  } else if (data.type === 'port_scan') {
    formattedResults = formatPortScanResults(data.results);
  } else if (data.type === 'vuln_scan') {
    formattedResults = formatVulnScanResults(data.results);
  } else if (data.type === 'social_media') {
    formattedResults = formatSocialMediaResults(data.results);
  } else {
    formattedResults = JSON.stringify(data.results, null, 2);
  }
  
  // Update results
  resultsOutput.textContent = formattedResults;
  
  // Show notification
  ui.showToast(`New ${data.type} results received`, 'info');
}

/**
 * Format domain reconnaissance results
 */
function formatDomainReconResults(results) {
  if (!results || !results.domain) {
    return 'No results found';
  }
  
  let output = `Domain Reconnaissance Results for ${results.domain}\n`;
  output += '='.repeat(output.length) + '\n\n';
  
  if (results.whois) {
    output += 'WHOIS Information:\n';
    output += '-'.repeat(18) + '\n';
    for (const [key, value] of Object.entries(results.whois)) {
      output += `${key}: ${value}\n`;
    }
    output += '\n';
  }
  
  if (results.dns) {
    output += 'DNS Records:\n';
    output += '-'.repeat(12) + '\n';
    for (const record of results.dns) {
      output += `${record.type}: ${record.value} (TTL: ${record.ttl})\n`;
    }
    output += '\n';
  }
  
  if (results.subdomains && results.subdomains.length > 0) {
    output += 'Subdomains:\n';
    output += '-'.repeat(11) + '\n';
    for (const subdomain of results.subdomains) {
      output += `${subdomain}\n`;
    }
    output += '\n';
  }
  
  return output;
}

/**
 * Format port scan results
 */
function formatPortScanResults(results) {
  if (!results || !results.target) {
    return 'No results found';
  }
  
  let output = `Port Scan Results for ${results.target}\n`;
  output += '='.repeat(output.length) + '\n\n';
  
  if (results.ports && results.ports.length > 0) {
    output += 'Open Ports:\n';
    output += '-'.repeat(11) + '\n';
    output += 'PORT\tSTATE\tSERVICE\tVERSION\n';
    
    for (const port of results.ports) {
      output += `${port.number}/${port.protocol}\t${port.state}\t${port.service}\t${port.version || 'unknown'}\n`;
    }
    output += '\n';
  } else {
    output += 'No open ports found\n\n';
  }
  
  if (results.os) {
    output += 'OS Detection:\n';
    output += '-'.repeat(13) + '\n';
    output += `Name: ${results.os.name}\n`;
    output += `Accuracy: ${results.os.accuracy}%\n\n`;
  }
  
  return output;
}

/**
 * Format vulnerability scan results
 */
function formatVulnScanResults(results) {
  if (!results || !results.target) {
    return 'No results found';
  }
  
  let output = `Vulnerability Scan Results for ${results.target}\n`;
  output += '='.repeat(output.length) + '\n\n';
  
  if (results.vulnerabilities && results.vulnerabilities.length > 0) {
    output += 'Vulnerabilities:\n';
    output += '-'.repeat(15) + '\n';
    
    for (const vuln of results.vulnerabilities) {
      output += `ID: ${vuln.id}\n`;
      output += `Name: ${vuln.name}\n`;
      output += `Severity: ${vuln.severity}\n`;
      output += `Description: ${vuln.description}\n`;
      if (vuln.solution) {
        output += `Solution: ${vuln.solution}\n`;
      }
      output += '\n';
    }
  } else {
    output += 'No vulnerabilities found\n\n';
  }
  
  return output;
}

/**
 * Format social media search results
 */
function formatSocialMediaResults(results) {
  if (!results || !results.query) {
    return 'No results found';
  }
  
  let output = `Social Media Search Results for "${results.query}"\n`;
  output += '='.repeat(output.length) + '\n\n';
  
  if (results.profiles && results.profiles.length > 0) {
    output += 'Profiles Found:\n';
    output += '-'.repeat(15) + '\n';
    
    for (const profile of results.profiles) {
      output += `Platform: ${profile.platform}\n`;
      output += `Username: ${profile.username}\n`;
      output += `URL: ${profile.url}\n`;
      if (profile.fullName) {
        output += `Full Name: ${profile.fullName}\n`;
      }
      if (profile.bio) {
        output += `Bio: ${profile.bio}\n`;
      }
      output += '\n';
    }
  } else {
    output += 'No profiles found\n\n';
  }
  
  return output;
}

/**
 * Start refresh interval for real-time updates
 */
function startRefreshInterval() {
  // Clear any existing interval
  if (refreshInterval) {
    clearInterval(refreshInterval);
  }
  
  // Set new interval (every 30 seconds)
  refreshInterval = setInterval(() => {
    checkSystemStatus();
    tasks.loadScheduledTasks();
  }, 30000);
}

/**
 * Export results to different formats
 */
function exportResults(format) {
  const resultsOutput = document.getElementById('results-output');
  if (!resultsOutput) return;
  
  const content = resultsOutput.textContent;
  if (!content || content === 'Results cleared.') {
    ui.showToast('No results to export', 'warning');
    return;
  }
  
  let exportContent = '';
  let mimeType = '';
  let fileExtension = '';
  
  switch (format) {
    case 'json':
      try {
        // Try to parse as JSON first
        const jsonObj = JSON.parse(content);
        exportContent = JSON.stringify(jsonObj, null, 2);
      } catch (e) {
        // If not valid JSON, create a simple JSON object
        exportContent = JSON.stringify({ results: content }, null, 2);
      }
      mimeType = 'application/json';
      fileExtension = 'json';
      break;
      
    case 'csv':
      // Simple conversion to CSV
      exportContent = content.split('\n').map(line => {
        // Replace multiple spaces with a single comma
        return line.replace(/\s{2,}/g, ',');
      }).join('\n');
      mimeType = 'text/csv';
      fileExtension = 'csv';
      break;
      
    case 'txt':
    default:
      exportContent = content;
      mimeType = 'text/plain';
      fileExtension = 'txt';
      break;
  }
  
  // Create download link
  const blob = new Blob([exportContent], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `cyberops-results-${timestamp}.${fileExtension}`;
  
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.style.display = 'none';
  
  document.body.appendChild(link);
  link.click();
  
  // Clean up
  setTimeout(() => {
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }, 100);
  
  ui.showToast(`Results exported as ${format.toUpperCase()}`, 'success');
}

// Export module functions
export default {
  initializeWebSocket,
  checkSystemStatus,
  updateSystemStatus,
  updateScanResults,
  startRefreshInterval,
  exportResults
};
