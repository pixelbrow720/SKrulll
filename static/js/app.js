/**
 * CyberOps Dashboard - Main JavaScript
 * Provides dynamic functionality for the dashboard
 */

// Main app object
const app = {
    // Initialize the application
    init: function() {
        console.log('Initializing CyberOps Dashboard...');
        
        // Initialize Feather icons
        this.initIcons();
        
        // Initialize theme toggle
        this.initThemeToggle();
        
        // Initialize AJAX forms
        this.initAjaxForms();
        
        // Initialize real-time updates
        this.initRealTimeUpdates();
        
        // Initialize tooltips and popovers
        this.initTooltips();
        
        console.log('CyberOps Dashboard initialized');
    },
    
    // Initialize Feather icons
    initIcons: function() {
        if (typeof feather !== 'undefined') {
            feather.replace({ 'aria-hidden': 'true' });
        }
    },
    
    // Initialize theme toggle
    initThemeToggle: function() {
        const themeToggle = document.getElementById('theme-toggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', function() {
                const htmlElement = document.documentElement;
                const currentTheme = htmlElement.getAttribute('data-bs-theme');
                const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
                
                // Update theme attribute
                htmlElement.setAttribute('data-bs-theme', newTheme);
                
                // Update icon
                const icon = themeToggle.querySelector('i');
                if (icon) {
                    if (newTheme === 'dark') {
                        icon.setAttribute('data-feather', 'moon');
                    } else {
                        icon.setAttribute('data-feather', 'sun');
                    }
                    feather.replace({ 'aria-hidden': 'true' });
                }
                
                // Save preference in localStorage
                localStorage.setItem('theme', newTheme);
                
                // Show notification
                app.showNotification('Theme Changed', `Switched to ${newTheme} theme`, 'info');
            });
            
            // Set initial icon based on current theme
            const currentTheme = document.documentElement.getAttribute('data-bs-theme');
            const icon = themeToggle.querySelector('i');
            if (icon) {
                if (currentTheme === 'dark') {
                    icon.setAttribute('data-feather', 'moon');
                } else {
                    icon.setAttribute('data-feather', 'sun');
                }
                feather.replace({ 'aria-hidden': 'true' });
            }
        }
    },
    
    // Initialize AJAX forms
    initAjaxForms: function() {
        document.querySelectorAll('form[data-ajax="true"]').forEach(form => {
            form.addEventListener('submit', function(e) {
                e.preventDefault();
                
                // Get form data
                const formData = new FormData(form);
                const jsonData = {};
                
                // Convert FormData to JSON
                formData.forEach((value, key) => {
                    // Handle special cases
                    if (key === 'options' && value) {
                        try {
                            jsonData[key] = JSON.parse(value);
                        } catch (error) {
                            jsonData[key] = value;
                        }
                    } else {
                        jsonData[key] = value;
                    }
                });
                
                // Get form attributes
                const url = form.getAttribute('action') || window.location.href;
                const method = form.getAttribute('method') || 'POST';
                const resultsTarget = form.getAttribute('data-results-target');
                const resetOnSuccess = form.getAttribute('data-reset-on-success') === 'true';
                const successCallback = form.getAttribute('data-success-callback');
                
                // Show loading state
                const submitButton = form.querySelector('button[type="submit"]');
                if (submitButton) {
                    const originalText = submitButton.innerHTML;
                    submitButton.disabled = true;
                    submitButton.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Loading...';
                }
                
                // Make AJAX request
                fetch(url, {
                    method: method,
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': formData.get('csrf_token') || ''
                    },
                    body: JSON.stringify(jsonData)
                })
                .then(response => response.json())
                .then(result => {
                    // Reset loading state
                    if (submitButton) {
                        submitButton.disabled = false;
                        submitButton.innerHTML = originalText;
                    }
                    
                    // Handle success
                    if (result.status === 'success') {
                        // Show success notification
                        app.showNotification('Success', result.message, 'success');
                        
                        // Update results if target specified
                        if (resultsTarget) {
                            const resultsElement = document.querySelector(resultsTarget);
                            if (resultsElement) {
                                app.updateResults(resultsElement, result.data);
                            }
                        }
                        
                        // Reset form if specified
                        if (resetOnSuccess) {
                            form.reset();
                        }
                        
                        // Call success callback if specified
                        if (successCallback && typeof window[successCallback] === 'function') {
                            window[successCallback](result);
                        }
                    } else {
                        // Handle error
                        app.showNotification('Error', result.message, 'danger');
                        console.error('Form submission error:', result);
                    }
                })
                .catch(error => {
                    // Reset loading state
                    if (submitButton) {
                        submitButton.disabled = false;
                        submitButton.innerHTML = originalText;
                    }
                    
                    // Show error notification
                    app.showNotification('Error', 'An error occurred while submitting the form', 'danger');
                    console.error('Form submission error:', error);
                });
            });
        });
    },
    
    // Initialize real-time updates
    initRealTimeUpdates: function() {
        // Check for tasks that need real-time updates
        const runningTasks = document.querySelectorAll('tr[data-task-id] .task-status.running');
        if (runningTasks.length > 0) {
            // Collect task IDs
            const taskIds = Array.from(runningTasks).map(status => {
                const row = status.closest('tr[data-task-id]');
                return row.getAttribute('data-task-id');
            });
            
            // Set up polling for task status updates
            if (taskIds.length > 0) {
                this.pollTaskStatus(taskIds);
            }
        }
    },
    
    // Poll for task status updates
    pollTaskStatus: function(taskIds, interval = 5000) {
        // Set up interval for polling
        const statusInterval = setInterval(() => {
            // Make API request to get task status
            fetch('/api/tasks/status', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
                },
                body: JSON.stringify({ task_ids: taskIds })
            })
            .then(response => response.json())
            .then(result => {
                if (result.status === 'success' && result.data && result.data.tasks) {
                    // Update task status in the UI
                    result.data.tasks.forEach(task => {
                        const row = document.querySelector(`tr[data-task-id="${task.id}"]`);
                        if (row) {
                            const statusElement = row.querySelector('.task-status');
                            const statusTextElement = row.querySelector('.task-status-text');
                            const progressElement = row.querySelector('.progress-bar');
                            
                            // Update status class
                            if (statusElement && task.status) {
                                // Remove all status classes
                                statusElement.classList.remove('running', 'completed', 'failed', 'scheduled', 'cancelled');
                                // Add new status class
                                statusElement.classList.add(task.status);
                            }
                            
                            // Update status text
                            if (statusTextElement && task.status) {
                                statusTextElement.textContent = task.status;
                            }
                            
                            // Update progress if available
                            if (progressElement && task.progress !== undefined) {
                                progressElement.style.width = `${task.progress}%`;
                                progressElement.setAttribute('aria-valuenow', task.progress);
                                
                                // Update progress text
                                const progressTextElement = row.querySelector('small');
                                if (progressTextElement) {
                                    progressTextElement.textContent = `${task.progress}%`;
                                }
                            }
                            
                            // If task is no longer running, remove it from the polling list
                            if (task.status !== 'running') {
                                taskIds = taskIds.filter(id => id !== task.id);
                                
                                // Show notification for completed tasks
                                if (task.status === 'completed') {
                                    app.showNotification('Task Completed', `Task ${task.id} has completed successfully`, 'success');
                                } else if (task.status === 'failed') {
                                    app.showNotification('Task Failed', `Task ${task.id} has failed`, 'danger');
                                }
                            }
                        }
                    });
                    
                    // If no more running tasks, clear the interval
                    if (taskIds.length === 0) {
                        clearInterval(statusInterval);
                    }
                }
            })
            .catch(error => {
                console.error('Error polling task status:', error);
            });
        }, interval);
    },
    
    // Update results container
    updateResults: function(element, data) {
        if (!element || !data) return;
        
        // Clear previous results
        element.innerHTML = '';
        
        // Create results content
        if (data.task) {
            // Task result
            const task = data.task;
            
            // Create task info
            const taskInfo = document.createElement('div');
            taskInfo.className = 'task-info mb-3';
            taskInfo.innerHTML = `
                <h5>Task Created</h5>
                <p><strong>ID:</strong> ${task.id}</p>
                <p><strong>Name:</strong> ${task.name}</p>
                <p><strong>Status:</strong> <span class="badge bg-warning">${task.status}</span></p>
            `;
            
            // Create task details
            const taskDetails = document.createElement('div');
            taskDetails.className = 'task-details';
            taskDetails.innerHTML = `
                <pre class="mb-0">${JSON.stringify(task, null, 2)}</pre>
            `;
            
            // Add to results
            element.appendChild(taskInfo);
            element.appendChild(taskDetails);
            
            // If task is running, set up polling for updates
            if (task.status === 'scheduled' || task.status === 'running') {
                this.pollTaskStatus([task.id]);
            }
        } else {
            // Generic result
            const resultPre = document.createElement('pre');
            resultPre.className = 'mb-0';
            resultPre.textContent = JSON.stringify(data, null, 2);
            element.appendChild(resultPre);
        }
    },
    
    // Initialize tooltips and popovers
    initTooltips: function() {
        // Initialize Bootstrap tooltips
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
        
        // Initialize Bootstrap popovers
        const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
        popoverTriggerList.map(function (popoverTriggerEl) {
            return new bootstrap.Popover(popoverTriggerEl);
        });
    },
    
    // Show notification toast
    showNotification: function(title, message, type = 'info') {
        // Create toast container if it doesn't exist
        let toastContainer = document.querySelector('.toast-container');
        if (!toastContainer) {
            toastContainer = document.createElement('div');
            toastContainer.className = 'toast-container position-fixed bottom-0 end-0 p-3';
            document.body.appendChild(toastContainer);
        }
        
        // Create unique ID for the toast
        const toastId = 'toast-' + Date.now();
        
        // Create toast element
        const toastHtml = `
            <div id="${toastId}" class="toast" role="alert" aria-live="assertive" aria-atomic="true">
                <div class="toast-header bg-${type} bg-opacity-10 text-${type}">
                    <strong class="me-auto">${title}</strong>
                    <small>Just now</small>
                    <button type="button" class="btn-close" data-bs-dismiss="toast" aria-label="Close"></button>
                </div>
                <div class="toast-body">
                    ${message}
                </div>
            </div>
        `;
        
        // Add toast to container
        toastContainer.insertAdjacentHTML('beforeend', toastHtml);
        
        // Initialize and show the toast
        const toastElement = document.getElementById(toastId);
        const toast = new bootstrap.Toast(toastElement, {
            autohide: true,
            delay: 5000
        });
        toast.show();
        
        // Remove toast from DOM after it's hidden
        toastElement.addEventListener('hidden.bs.toast', function () {
            toastElement.remove();
        });
    }
};

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    app.init();
});
