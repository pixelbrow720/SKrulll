/**
 * Tasks module for CyberOps Dashboard
 * Handles task scheduling, management, and status updates
 */

/**
 * Load scheduled tasks
 */
function loadScheduledTasks() {
  api.fetchWithAuth('/api/schedule/list')
    .then(response => response.json())
    .then(data => {
      const tasksList = document.getElementById('tasks-list');
      if (!tasksList) return;
      
      if (data.status === 'success' && data.data.tasks && data.data.tasks.length > 0) {
        // Clear existing tasks
        tasksList.innerHTML = '';
        
        // Add tasks
        data.data.tasks.forEach(task => {
          const taskItem = document.createElement('tr');
          taskItem.className = 'search-item';
          
          // Determine task status class
          let statusClass = 'scheduled';
          if (task.status === 'running') {
            statusClass = 'running';
          } else if (task.status === 'completed') {
            statusClass = 'completed';
          } else if (task.status === 'failed') {
            statusClass = 'failed';
          }
          
          // Format schedule
          let schedule = '';
          if (task.interval) {
            schedule = `Every ${task.interval} seconds`;
          } else if (task.cron) {
            schedule = `Cron: ${task.cron}`;
          }
          
          taskItem.innerHTML = `
            <td><span class="task-status ${statusClass}"></span> ${task.name}</td>
            <td class="task-name">${task.command}</td>
            <td>${schedule}</td>
            <td>
              <button class="btn btn-sm btn-outline-danger" onclick="tasks.removeTask('${task.name}')">
                <i data-feather="trash-2"></i>
              </button>
            </td>
          `;
          
          tasksList.appendChild(taskItem);
        });
        
        // Initialize feather icons
        feather.replace();
      } else {
        tasksList.innerHTML = '<tr><td colspan="4" class="text-center">No scheduled tasks found</td></tr>';
      }
    })
    .catch(error => {
      console.error('Error loading tasks:', error);
      const tasksList = document.getElementById('tasks-list');
      if (tasksList) {
        tasksList.innerHTML = '<tr><td colspan="4" class="text-center text-danger">Error loading tasks</td></tr>';
      }
    });
}

/**
 * Remove a scheduled task
 */
function removeTask(name) {
  if (!confirm(`Are you sure you want to remove the task "${name}"?`)) {
    return;
  }
  
  api.fetchWithAuth(`/api/schedule/remove?name=${encodeURIComponent(name)}`)
    .then(response => response.json())
    .then(data => {
      if (data.status === 'success') {
        ui.showToast(`Task "${name}" removed successfully`, 'success');
        loadScheduledTasks();
      } else {
        ui.showToast(`Failed to remove task: ${data.message}`, 'error');
      }
    })
    .catch(error => {
      console.error('Error removing task:', error);
      ui.showToast('Error removing task', 'error');
    });
}

/**
 * Schedule a new task
 */
function scheduleTask() {
  const taskName = document.getElementById('task-name').value;
  const taskCommand = document.getElementById('task-command').value;
  const taskDescription = document.getElementById('task-description').value;
  
  // Get schedule type
  const intervalType = document.getElementById('interval-type');
  const useInterval = intervalType.checked;
  
  let interval = null;
  let cron = null;
  
  if (useInterval) {
    interval = parseInt(document.getElementById('interval-seconds').value);
  } else {
    cron = document.getElementById('cron-expression').value;
  }
  
  // Validate inputs
  if (!taskName || !taskCommand) {
    ui.showToast('Please fill in all required fields', 'error');
    return;
  }
  
  if (useInterval && (!interval || isNaN(interval) || interval < 1)) {
    ui.showToast('Please enter a valid interval (seconds)', 'error');
    return;
  }
  
  if (!useInterval && !cron) {
    ui.showToast('Please enter a cron expression', 'error');
    return;
  }
  
  // Prepare request data
  const requestData = {
    name: taskName,
    command: taskCommand,
    description: taskDescription
  };
  
  if (useInterval) {
    requestData.interval = interval;
  } else {
    requestData.cron = cron;
  }
  
  // Send request
  api.fetchWithAuth('/api/schedule/add', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(requestData)
  })
    .then(response => response.json())
    .then(data => {
      if (data.status === 'success') {
        ui.showToast('Task scheduled successfully', 'success');
        
        // Clear form
        document.getElementById('task-name').value = '';
        document.getElementById('task-command').value = '';
        document.getElementById('task-description').value = '';
        document.getElementById('interval-seconds').value = '60';
        document.getElementById('cron-expression').value = '* * * * *';
        
        // Reload tasks
        loadScheduledTasks();
      } else {
        ui.showToast(`Failed to schedule task: ${data.message}`, 'error');
      }
    })
    .catch(error => {
      console.error('Error scheduling task:', error);
      ui.showToast('Error scheduling task', 'error');
    });
}

/**
 * Update task status from WebSocket data
 */
function updateTaskStatus(data) {
  if (!data || !data.name) return;
  
  // Find task in the list
  const tasksList = document.getElementById('tasks-list');
  if (!tasksList) return;
  
  const taskRows = tasksList.querySelectorAll('tr');
  for (const row of taskRows) {
    const nameCell = row.querySelector('td:first-child');
    if (nameCell && nameCell.textContent.includes(data.name)) {
      // Update status indicator
      const statusIndicator = nameCell.querySelector('.task-status');
      if (statusIndicator) {
        // Remove all status classes
        statusIndicator.classList.remove('scheduled', 'running', 'completed', 'failed');
        
        // Add appropriate class
        let statusClass = 'scheduled';
        if (data.status === 'running') {
          statusClass = 'running';
        } else if (data.status === 'completed') {
          statusClass = 'completed';
        } else if (data.status === 'failed') {
          statusClass = 'failed';
        }
        
        statusIndicator.classList.add(statusClass);
      }
      
      // Show notification for status changes
      if (data.status === 'completed') {
        ui.showToast(`Task "${data.name}" completed successfully`, 'success');
      } else if (data.status === 'failed') {
        ui.showToast(`Task "${data.name}" failed: ${data.error || 'Unknown error'}`, 'error');
      } else if (data.status === 'running') {
        ui.showToast(`Task "${data.name}" is now running`, 'info');
      }
      
      break;
    }
  }
}

/**
 * Perform domain reconnaissance
 */
function performDomainRecon() {
  const domainInput = document.getElementById('domain-input');
  if (!domainInput) return;
  
  const domain = domainInput.value.trim();
  if (!domain) {
    ui.showToast('Please enter a domain', 'error');
    return;
  }
  
  // Validate domain format
  const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  if (!domainRegex.test(domain)) {
    ui.showToast('Please enter a valid domain name', 'error');
    return;
  }
  
  // Show loading indicator
  const resultsOutput = document.getElementById('results-output');
  if (resultsOutput) {
    resultsOutput.textContent = 'Running domain reconnaissance...';
  }
  
  // Send request
  api.fetchWithAuth(`/api/osint/domain?domain=${encodeURIComponent(domain)}`)
    .then(response => response.json())
    .then(data => {
      if (data.status === 'success') {
        if (data.data.async) {
          // Async task started
          ui.showToast('Domain reconnaissance started. Results will be available soon.', 'info');
        } else {
          // Immediate results
          displayDomainReconResults(data.data);
        }
      } else {
        ui.showToast(`Failed to start domain reconnaissance: ${data.message}`, 'error');
        if (resultsOutput) {
          resultsOutput.textContent = `Error: ${data.message}`;
        }
      }
    })
    .catch(error => {
      console.error('Error performing domain recon:', error);
      ui.showToast('Error performing domain reconnaissance', 'error');
      if (resultsOutput) {
        resultsOutput.textContent = 'Error performing domain reconnaissance';
      }
    });
}

/**
 * Display domain reconnaissance results
 */
function displayDomainReconResults(results) {
  const resultsOutput = document.getElementById('results-output');
  if (!resultsOutput) return;
  
  if (!results || !results.domain) {
    resultsOutput.textContent = 'No results found';
    return;
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
  
  resultsOutput.textContent = output;
}

/**
 * Perform social media search
 */
function performSocialMediaSearch() {
  const usernameInput = document.getElementById('username-input');
  if (!usernameInput) return;
  
  const username = usernameInput.value.trim();
  if (!username) {
    ui.showToast('Please enter a username', 'error');
    return;
  }
  
  // Show loading indicator
  const resultsOutput = document.getElementById('results-output');
  if (resultsOutput) {
    resultsOutput.textContent = 'Searching social media profiles...';
  }
  
  // Send request
  api.fetchWithAuth(`/api/osint/social?username=${encodeURIComponent(username)}`)
    .then(response => response.json())
    .then(data => {
      if (data.status === 'success') {
        if (data.data.async) {
          // Async task started
          ui.showToast('Social media search started. Results will be available soon.', 'info');
        } else {
          // Immediate results
          displaySocialMediaResults(data.data);
        }
      } else {
        ui.showToast(`Failed to start social media search: ${data.message}`, 'error');
        if (resultsOutput) {
          resultsOutput.textContent = `Error: ${data.message}`;
        }
      }
    })
    .catch(error => {
      console.error('Error performing social media search:', error);
      ui.showToast('Error performing social media search', 'error');
      if (resultsOutput) {
        resultsOutput.textContent = 'Error performing social media search';
      }
    });
}

/**
 * Display social media search results
 */
function displaySocialMediaResults(results) {
  const resultsOutput = document.getElementById('results-output');
  if (!resultsOutput) return;
  
  if (!results || !results.query) {
    resultsOutput.textContent = 'No results found';
    return;
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
  
  resultsOutput.textContent = output;
}

/**
 * Perform port scan
 */
function performPortScan() {
  const targetInput = document.getElementById('target-input');
  const portRangeInput = document.getElementById('port-range');
  
  if (!targetInput || !portRangeInput) return;
  
  const target = targetInput.value.trim();
  const portRange = portRangeInput.value.trim();
  
  if (!target) {
    ui.showToast('Please enter a target IP or domain', 'error');
    return;
  }
  
  // Show loading indicator
  const resultsOutput = document.getElementById('results-output');
  if (resultsOutput) {
    resultsOutput.textContent = 'Running port scan...';
  }
  
  // Prepare request data
  const requestData = {
    target: target,
    ports: portRange || '1-1000'
  };
  
  // Send request
  api.fetchWithAuth('/api/security/port-scan', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(requestData)
  })
    .then(response => response.json())
    .then(data => {
      if (data.status === 'success') {
        if (data.data.async) {
          // Async task started
          ui.showToast('Port scan started. Results will be available soon.', 'info');
        } else {
          // Immediate results
          displayPortScanResults(data.data);
        }
      } else {
        ui.showToast(`Failed to start port scan: ${data.message}`, 'error');
        if (resultsOutput) {
          resultsOutput.textContent = `Error: ${data.message}`;
        }
      }
    })
    .catch(error => {
      console.error('Error performing port scan:', error);
      ui.showToast('Error performing port scan', 'error');
      if (resultsOutput) {
        resultsOutput.textContent = 'Error performing port scan';
      }
    });
}

/**
 * Display port scan results
 */
function displayPortScanResults(results) {
  const resultsOutput = document.getElementById('results-output');
  if (!resultsOutput) return;
  
  if (!results || !results.target) {
    resultsOutput.textContent = 'No results found';
    return;
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
  
  resultsOutput.textContent = output;
}

/**
 * Perform vulnerability scan
 */
function performVulnScan() {
  const targetInput = document.getElementById('vuln-target-input');
  if (!targetInput) return;
  
  const target = targetInput.value.trim();
  if (!target) {
    ui.showToast('Please enter a target IP or domain', 'error');
    return;
  }
  
  // Show loading indicator
  const resultsOutput = document.getElementById('results-output');
  if (resultsOutput) {
    resultsOutput.textContent = 'Running vulnerability scan...';
  }
  
  // Send request
  api.fetchWithAuth(`/api/security/vuln-scan?target=${encodeURIComponent(target)}`)
    .then(response => response.json())
    .then(data => {
      if (data.status === 'success') {
        if (data.data.async) {
          // Async task started
          ui.showToast('Vulnerability scan started. Results will be available soon.', 'info');
        } else {
          // Immediate results
          displayVulnScanResults(data.data);
        }
      } else {
        ui.showToast(`Failed to start vulnerability scan: ${data.message}`, 'error');
        if (resultsOutput) {
          resultsOutput.textContent = `Error: ${data.message}`;
        }
      }
    })
    .catch(error => {
      console.error('Error performing vulnerability scan:', error);
      ui.showToast('Error performing vulnerability scan', 'error');
      if (resultsOutput) {
        resultsOutput.textContent = 'Error performing vulnerability scan';
      }
    });
}

/**
 * Display vulnerability scan results
 */
function displayVulnScanResults(results) {
  const resultsOutput = document.getElementById('results-output');
  if (!resultsOutput) return;
  
  if (!results || !results.target) {
    resultsOutput.textContent = 'No results found';
    return;
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
  
  resultsOutput.textContent = output;
}

// Export module functions
export default {
  loadScheduledTasks,
  removeTask,
  scheduleTask,
  updateTaskStatus,
  performDomainRecon,
  displayDomainReconResults,
  performSocialMediaSearch,
  displaySocialMediaResults,
  performPortScan,
  displayPortScanResults,
  performVulnScan,
  displayVulnScanResults
};
