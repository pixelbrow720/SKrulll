/**
 * CyberOps Dashboard Main JavaScript
 * Entry point for the application
 */

// Import modules
import core from './modules/core.js';
import auth from './modules/auth.js';
import ui from './modules/ui.js';
import tasks from './modules/tasks.js';
import api from './modules/api.js';

// Make modules globally accessible
window.core = core;
window.auth = auth;
window.ui = ui;
window.tasks = tasks;
window.api = api;

// Initialize application
document.addEventListener('DOMContentLoaded', function() {
  // Initialize Feather icons
  feather.replace();
  
  // Initialize UI components
  ui.initializeUI();
  
  // Check authentication status
  auth.checkAuthStatus();
  
  // Check system status
  core.checkSystemStatus();
  
  // Load scheduled tasks
  tasks.loadScheduledTasks();
  
  // Start refresh interval for real-time updates
  core.startRefreshInterval();
  
  // Initialize WebSocket connection for real-time updates if supported
  core.initializeWebSocket();
  
  // Set up event listeners for forms
  setupFormEventListeners();
  
  console.log('CyberOps Dashboard initialized');
});

/**
 * Set up event listeners for forms
 */
function setupFormEventListeners() {
  // Domain reconnaissance form
  const domainReconForm = document.getElementById('domain-recon-form');
  if (domainReconForm) {
    domainReconForm.addEventListener('submit', function(event) {
      event.preventDefault();
      tasks.performDomainRecon();
    });
  }
  
  // Social media form
  const socialMediaForm = document.getElementById('social-media-form');
  if (socialMediaForm) {
    socialMediaForm.addEventListener('submit', function(event) {
      event.preventDefault();
      tasks.performSocialMediaSearch();
    });
  }
  
  // Port scan form
  const portScanForm = document.getElementById('port-scan-form');
  if (portScanForm) {
    portScanForm.addEventListener('submit', function(event) {
      event.preventDefault();
      tasks.performPortScan();
    });
  }
  
  // Vulnerability scan form
  const vulnScanForm = document.getElementById('vuln-scan-form');
  if (vulnScanForm) {
    vulnScanForm.addEventListener('submit', function(event) {
      event.preventDefault();
      tasks.performVulnScan();
    });
  }
  
  // Scheduler form
  const schedulerForm = document.getElementById('scheduler-form');
  if (schedulerForm) {
    schedulerForm.addEventListener('submit', function(event) {
      event.preventDefault();
      tasks.scheduleTask();
    });
  }
  
  // Schedule type selector
  const intervalType = document.getElementById('interval-type');
  const cronType = document.getElementById('cron-type');
  const intervalInput = document.getElementById('interval-input');
  const cronInput = document.getElementById('cron-input');
  
  if (intervalType && cronType && intervalInput && cronInput) {
    intervalType.addEventListener('change', function() {
      intervalInput.style.display = 'block';
      cronInput.style.display = 'none';
    });
    
    cronType.addEventListener('change', function() {
      intervalInput.style.display = 'none';
      cronInput.style.display = 'block';
    });
  }
}
