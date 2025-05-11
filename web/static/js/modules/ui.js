/**
 * UI module for SKrulll Dashboard
 * Handles UI elements, animations, and visual effects
 */

// Global variables
let darkMode = localStorage.getItem('darkMode') === 'false' ? false : true; // Default to dark mode

/**
 * Apply theme based on preference
 */
function applyTheme() {
  const html = document.documentElement;
  
  if (darkMode) {
    html.setAttribute('data-bs-theme', 'dark');
  } else {
    html.setAttribute('data-bs-theme', 'light');
  }
}

/**
 * Add theme toggle button to navbar
 */
function addThemeToggle() {
  const navbarNav = document.querySelector('.navbar-nav');
  if (!navbarNav) return;
  
  // Check if theme toggle already exists
  if (document.getElementById('theme-toggle')) return;
  
  // Create theme toggle button
  const themeToggleHtml = `
    <li class="nav-item ms-2">
      <button id="theme-toggle" class="btn btn-sm btn-outline-secondary rounded-circle" title="Toggle theme">
        <i data-feather="${darkMode ? 'moon' : 'sun'}"></i>
      </button>
    </li>
  `;
  
  navbarNav.insertAdjacentHTML('beforeend', themeToggleHtml);
  
  // Initialize feather icons
  feather.replace();
  
  // Add event listener
  const themeToggle = document.getElementById('theme-toggle');
  if (themeToggle) {
    themeToggle.addEventListener('click', toggleTheme);
  }
}

/**
 * Toggle between light and dark theme
 */
function toggleTheme() {
  const html = document.documentElement;
  const themeIcon = document.querySelector('#theme-toggle i');
  
  if (darkMode) {
    // Switch to light mode
    html.setAttribute('data-bs-theme', 'light');
    if (themeIcon) {
      themeIcon.setAttribute('data-feather', 'sun');
    }
  } else {
    // Switch to dark mode
    html.setAttribute('data-bs-theme', 'dark');
    if (themeIcon) {
      themeIcon.setAttribute('data-feather', 'moon');
    }
  }
  
  // Toggle state
  darkMode = !darkMode;
  
  // Update feather icons
  feather.replace();
  
  // Save preference
  localStorage.setItem('darkMode', darkMode ? 'true' : 'false');
}

/**
 * Add animated background to the page
 */
function addAnimatedBackground() {
  // Check if animated background already exists
  if (document.getElementById('animated-background')) return;
  
  // Create animated background container
  const backgroundContainer = document.createElement('div');
  backgroundContainer.id = 'animated-background';
  backgroundContainer.className = 'animated-background';
  backgroundContainer.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    z-index: -1;
    pointer-events: none;
    overflow: hidden;
  `;
  
  // Add animated elements
  for (let i = 0; i < 5; i++) {
    const element = document.createElement('div');
    element.className = 'animated-element';
    
    // Random position, size, and animation
    const size = Math.floor(Math.random() * 200) + 100;
    const posX = Math.floor(Math.random() * 100);
    const posY = Math.floor(Math.random() * 100);
    const duration = Math.floor(Math.random() * 20) + 20;
    const delay = Math.floor(Math.random() * 10);
    
    element.style.cssText = `
      position: absolute;
      width: ${size}px;
      height: ${size}px;
      left: ${posX}%;
      top: ${posY}%;
      background: radial-gradient(circle, rgba(139, 92, 246, 0.05) 0%, transparent 70%);
      border-radius: 50%;
      animation: pulse ${duration}s ease-in-out ${delay}s infinite alternate;
      opacity: 0.3;
    `;
    
    backgroundContainer.appendChild(element);
  }
  
  // Add keyframes for animation
  const style = document.createElement('style');
  style.textContent = `
    @keyframes pulse {
      0% {
        transform: scale(0.8);
        opacity: 0.2;
      }
      100% {
        transform: scale(1.2);
        opacity: 0.4;
      }
    }
  `;
  
  document.head.appendChild(style);
  document.body.appendChild(backgroundContainer);
}

/**
 * Show toast notification
 */
function showToast(message, type = 'info') {
  // Check if toast container exists
  let toastContainer = document.querySelector('.toast-container');
  
  if (!toastContainer) {
    // Create toast container if it doesn't exist
    toastContainer = document.createElement('div');
    toastContainer.className = 'toast-container position-fixed bottom-0 end-0 p-3';
    toastContainer.style.zIndex = '1050';
    document.body.appendChild(toastContainer);
  }
  
  // Create toast element
  const toastId = 'toast-' + Date.now();
  const toast = document.createElement('div');
  toast.className = `toast show text-white bg-${type === 'error' ? 'danger' : type}`;
  toast.id = toastId;
  toast.setAttribute('role', 'alert');
  toast.setAttribute('aria-live', 'assertive');
  toast.setAttribute('aria-atomic', 'true');
  
  // Set toast icon based on type
  let icon = 'info';
  
  switch (type) {
    case 'success':
      icon = 'check-circle';
      break;
    case 'error':
      icon = 'alert-triangle';
      break;
    case 'warning':
      icon = 'alert-circle';
      break;
  }
  
  // Set toast content
  toast.innerHTML = `
    <div class="toast-header bg-${type === 'error' ? 'danger' : type} text-white">
      <i data-feather="${icon}" class="me-2"></i>
      <strong class="me-auto">${type.charAt(0).toUpperCase() + type.slice(1)}</strong>
      <small>just now</small>
      <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast" aria-label="Close"></button>
    </div>
    <div class="toast-body">
      ${message}
    </div>
  `;
  
  // Add toast to container
  toastContainer.appendChild(toast);
  
  // Initialize feather icons
  feather.replace();
  
  // Auto-remove toast after 5 seconds
  setTimeout(() => {
    const toastElement = document.getElementById(toastId);
    if (toastElement) {
      toastElement.remove();
    }
  }, 5000);
  
  // Add click event to close button
  const closeButton = toast.querySelector('.btn-close');
  if (closeButton) {
    closeButton.addEventListener('click', function() {
      toast.remove();
    });
  }
}

/**
 * Setup event listeners for UI elements
 */
function setupEventListeners() {
  // Clear results button
  const clearResultsBtn = document.getElementById('clear-results');
  if (clearResultsBtn) {
    clearResultsBtn.addEventListener('click', function() {
      const resultsOutput = document.getElementById('results-output');
      if (resultsOutput) {
        resultsOutput.textContent = 'Results cleared.';
      }
    });
  }
  
  // Add copy button to results
  const resultsOutput = document.getElementById('results-output');
  if (resultsOutput) {
    const copyBtn = document.createElement('button');
    copyBtn.className = 'btn btn-sm btn-outline-secondary position-absolute top-0 end-0 m-2';
    copyBtn.innerHTML = '<i data-feather="copy"></i>';
    copyBtn.title = 'Copy to clipboard';
    copyBtn.addEventListener('click', function() {
      navigator.clipboard.writeText(resultsOutput.textContent)
        .then(() => showToast('Copied to clipboard', 'success'))
        .catch(err => console.error('Failed to copy: ', err));
    });
    
    const resultsCard = resultsOutput.closest('.card-body');
    if (resultsCard) {
      resultsCard.style.position = 'relative';
      resultsCard.appendChild(copyBtn);
      feather.replace();
    }
  }
  
  // Add export buttons for results
  const resultsSection = document.getElementById('results-section');
  if (resultsSection) {
    const exportBtns = `
      <div class="btn-group btn-group-sm ms-2">
        <button class="btn btn-outline-secondary" onclick="core.exportResults('json')">
          <i data-feather="file-text"></i> JSON
        </button>
        <button class="btn btn-outline-secondary" onclick="core.exportResults('csv')">
          <i data-feather="file-text"></i> CSV
        </button>
        <button class="btn btn-outline-secondary" onclick="core.exportResults('txt')">
          <i data-feather="file-text"></i> TXT
        </button>
      </div>
    `;
    
    const clearBtn = resultsSection.querySelector('#clear-results');
    if (clearBtn) {
      clearBtn.insertAdjacentHTML('afterend', exportBtns);
      feather.replace();
    }
  }
  
  // Add search functionality to forms
  const searchInputs = document.querySelectorAll('.search-input');
  searchInputs.forEach(input => {
    input.addEventListener('input', function() {
      const searchTerm = this.value.toLowerCase();
      const targetId = this.getAttribute('data-search-target');
      const targetItems = document.querySelectorAll(`#${targetId} .search-item`);
      
      targetItems.forEach(item => {
        const text = item.textContent.toLowerCase();
        if (text.includes(searchTerm)) {
          item.style.display = '';
        } else {
          item.style.display = 'none';
        }
      });
    });
  });
  
  // Add filter functionality
  const filterButtons = document.querySelectorAll('.filter-btn');
  filterButtons.forEach(button => {
    button.addEventListener('click', function() {
      const filterValue = this.getAttribute('data-filter');
      const targetId = this.getAttribute('data-filter-target');
      const targetItems = document.querySelectorAll(`#${targetId} .filter-item`);
      
      // Update active button
      document.querySelectorAll(`[data-filter-target="${targetId}"]`).forEach(btn => {
        btn.classList.remove('active');
      });
      this.classList.add('active');
      
      // Filter items
      targetItems.forEach(item => {
        const itemType = item.getAttribute('data-type');
        if (filterValue === 'all' || itemType === filterValue) {
          item.style.display = '';
        } else {
          item.style.display = 'none';
        }
      });
    });
  });
  
  // Add collapsible sections
  const collapsibleHeaders = document.querySelectorAll('.collapsible-header');
  collapsibleHeaders.forEach(header => {
    header.addEventListener('click', function() {
      this.classList.toggle('active');
      const content = this.nextElementSibling;
      
      if (content.style.maxHeight) {
        content.style.maxHeight = null;
        this.querySelector('i').setAttribute('data-feather', 'chevron-down');
      } else {
        content.style.maxHeight = content.scrollHeight + 'px';
        this.querySelector('i').setAttribute('data-feather', 'chevron-up');
      }
      
      feather.replace();
    });
  });
}

/**
 * Initialize UI components
 */
function initializeUI() {
  // Apply theme
  applyTheme();
  
  // Add theme toggle
  addThemeToggle();
  
  // Add animated background
  addAnimatedBackground();
  
  // Setup event listeners
  setupEventListeners();
}

// Export module functions
export default {
  initializeUI,
  applyTheme,
  addThemeToggle,
  toggleTheme,
  addAnimatedBackground,
  showToast,
  setupEventListeners
};
