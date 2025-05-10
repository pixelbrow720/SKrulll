/**
 * API module for CyberOps Dashboard
 * Handles API communication and data fetching
 */

/**
 * Add authorization header to fetch requests
 */
function fetchWithAuth(url, options = {}) {
  if (!options.headers) {
    options.headers = {};
  }
  
  const authToken = auth.getAuthToken();
  if (authToken) {
    options.headers['Authorization'] = `Bearer ${authToken}`;
  }
  
  return fetch(url, options);
}

/**
 * Handle API errors
 */
function handleApiError(error, errorMessage = 'API request failed') {
  console.error(`${errorMessage}:`, error);
  ui.showToast(errorMessage, 'error');
  return { status: 'error', message: errorMessage };
}

/**
 * Fetch system status
 */
async function fetchSystemStatus() {
  try {
    const response = await fetchWithAuth('/api/system/status');
    return await response.json();
  } catch (error) {
    return handleApiError(error, 'Failed to fetch system status');
  }
}

/**
 * Fetch system information
 */
async function fetchSystemInfo() {
  try {
    const response = await fetchWithAuth('/api/system/info');
    return await response.json();
  } catch (error) {
    return handleApiError(error, 'Failed to fetch system information');
  }
}

/**
 * Fetch database status
 */
async function fetchDatabaseStatus() {
  try {
    const response = await fetchWithAuth('/api/db/status');
    return await response.json();
  } catch (error) {
    return handleApiError(error, 'Failed to fetch database status');
  }
}

/**
 * Fetch messaging status
 */
async function fetchMessagingStatus() {
  try {
    const response = await fetchWithAuth('/api/messaging/status');
    return await response.json();
  } catch (error) {
    return handleApiError(error, 'Failed to fetch messaging status');
  }
}

/**
 * Fetch scheduled tasks
 */
async function fetchScheduledTasks() {
  try {
    const response = await fetchWithAuth('/api/schedule/list');
    return await response.json();
  } catch (error) {
    return handleApiError(error, 'Failed to fetch scheduled tasks');
  }
}

/**
 * Add a scheduled task
 */
async function addScheduledTask(taskData) {
  try {
    const response = await fetchWithAuth('/api/schedule/add', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(taskData)
    });
    return await response.json();
  } catch (error) {
    return handleApiError(error, 'Failed to add scheduled task');
  }
}

/**
 * Remove a scheduled task
 */
async function removeScheduledTask(name) {
  try {
    const response = await fetchWithAuth(`/api/schedule/remove?name=${encodeURIComponent(name)}`);
    return await response.json();
  } catch (error) {
    return handleApiError(error, 'Failed to remove scheduled task');
  }
}

/**
 * Perform domain reconnaissance
 */
async function performDomainRecon(domain) {
  try {
    const response = await fetchWithAuth(`/api/osint/domain?domain=${encodeURIComponent(domain)}`);
    return await response.json();
  } catch (error) {
    return handleApiError(error, 'Failed to perform domain reconnaissance');
  }
}

/**
 * Perform social media search
 */
async function performSocialMediaSearch(username) {
  try {
    const response = await fetchWithAuth(`/api/osint/social?username=${encodeURIComponent(username)}`);
    return await response.json();
  } catch (error) {
    return handleApiError(error, 'Failed to perform social media search');
  }
}

/**
 * Perform port scan
 */
async function performPortScan(scanData) {
  try {
    const response = await fetchWithAuth('/api/security/port-scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(scanData)
    });
    return await response.json();
  } catch (error) {
    return handleApiError(error, 'Failed to perform port scan');
  }
}

/**
 * Perform vulnerability scan
 */
async function performVulnScan(target) {
  try {
    const response = await fetchWithAuth(`/api/security/vuln-scan?target=${encodeURIComponent(target)}`);
    return await response.json();
  } catch (error) {
    return handleApiError(error, 'Failed to perform vulnerability scan');
  }
}

/**
 * Verify authentication token
 */
async function verifyAuthToken(token) {
  try {
    const response = await fetch('/api/auth/verify', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    return await response.json();
  } catch (error) {
    return handleApiError(error, 'Failed to verify authentication token');
  }
}

/**
 * Login user
 */
async function login(credentials) {
  try {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(credentials)
    });
    return await response.json();
  } catch (error) {
    return handleApiError(error, 'Login failed');
  }
}

/**
 * Fetch scan results
 */
async function fetchScanResults(scanId) {
  try {
    const response = await fetchWithAuth(`/api/results/${scanId}`);
    return await response.json();
  } catch (error) {
    return handleApiError(error, 'Failed to fetch scan results');
  }
}

/**
 * Fetch recent scans
 */
async function fetchRecentScans() {
  try {
    const response = await fetchWithAuth('/api/scans/recent');
    return await response.json();
  } catch (error) {
    return handleApiError(error, 'Failed to fetch recent scans');
  }
}

/**
 * Fetch scan history
 */
async function fetchScanHistory(scanType, limit = 10) {
  try {
    const response = await fetchWithAuth(`/api/scans/history?type=${encodeURIComponent(scanType)}&limit=${limit}`);
    return await response.json();
  } catch (error) {
    return handleApiError(error, 'Failed to fetch scan history');
  }
}

/**
 * Export scan results
 */
async function exportScanResults(scanId, format = 'json') {
  try {
    const response = await fetchWithAuth(`/api/results/${scanId}/export?format=${format}`, {
      headers: {
        'Accept': format === 'json' ? 'application/json' : 'text/plain'
      }
    });
    
    if (format === 'json') {
      return await response.json();
    } else {
      return await response.text();
    }
  } catch (error) {
    return handleApiError(error, 'Failed to export scan results');
  }
}

// Export module functions
export default {
  fetchWithAuth,
  handleApiError,
  fetchSystemStatus,
  fetchSystemInfo,
  fetchDatabaseStatus,
  fetchMessagingStatus,
  fetchScheduledTasks,
  addScheduledTask,
  removeScheduledTask,
  performDomainRecon,
  performSocialMediaSearch,
  performPortScan,
  performVulnScan,
  verifyAuthToken,
  login,
  fetchScanResults,
  fetchRecentScans,
  fetchScanHistory,
  exportScanResults
};
