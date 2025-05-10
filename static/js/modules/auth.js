/**
 * Authentication module for SKrulll Dashboard
 * Handles user authentication, login, logout, and session management
 */

// Global variables
let authToken = localStorage.getItem('auth_token');

/**
 * Check authentication status
 */
function checkAuthStatus() {
  // If we have a token, verify it
  if (authToken) {
    fetch('/api/auth/verify', {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    })
    .then(response => {
      if (!response.ok) {
        throw new Error('Token invalid');
      }
      return response.json();
    })
    .then(data => {
      if (data.status === 'success') {
        // Update UI to show logged in state
        updateAuthUI(true, data.data.user);
      } else {
        // Clear invalid token
        localStorage.removeItem('auth_token');
        authToken = null;
        updateAuthUI(false);
      }
    })
    .catch(error => {
      console.error('Auth verification error:', error);
      localStorage.removeItem('auth_token');
      authToken = null;
      updateAuthUI(false);
    });
  } else {
    updateAuthUI(false);
  }
}

/**
 * Update UI based on authentication status
 */
function updateAuthUI(isAuthenticated, user = null) {
  const authSection = document.getElementById('auth-section');
  if (!authSection) return;
  
  if (isAuthenticated && user) {
    authSection.innerHTML = `
      <span class="navbar-text me-3">
        <i data-feather="user" class="me-1"></i> ${user.username} (${user.role})
      </span>
      <button class="btn btn-outline-danger btn-sm" onclick="auth.logout()">
        <i data-feather="log-out" class="me-1"></i> Logout
      </button>
    `;
  } else {
    authSection.innerHTML = `
      <button class="btn btn-outline-primary btn-sm" onclick="auth.showLoginModal()">
        <i data-feather="log-in" class="me-1"></i> Login
      </button>
    `;
  }
  
  // Re-initialize feather icons
  feather.replace();
  
  // Update secured elements visibility
  const securedElements = document.querySelectorAll('.secured-feature');
  securedElements.forEach(el => {
    if (isAuthenticated) {
      el.classList.remove('d-none');
    } else {
      el.classList.add('d-none');
    }
  });
  
  // Update role-specific elements
  if (isAuthenticated && user) {
    const adminElements = document.querySelectorAll('.admin-only');
    adminElements.forEach(el => {
      if (user.role === 'admin') {
        el.classList.remove('d-none');
      } else {
        el.classList.add('d-none');
      }
    });
  }
}

/**
 * Show login modal
 */
function showLoginModal() {
  // Check if modal already exists
  let loginModal = document.getElementById('login-modal');
  
  if (!loginModal) {
    // Create modal if it doesn't exist
    const modalHtml = `
      <div class="modal fade" id="login-modal" tabindex="-1" aria-labelledby="loginModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
          <div class="modal-content border-0 shadow">
            <div class="modal-header bg-primary text-white">
              <h5 class="modal-title" id="loginModalLabel">Login</h5>
              <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
              <form id="login-form">
                <div class="mb-3">
                  <label for="login-username" class="form-label">Username</label>
                  <div class="input-group">
                    <span class="input-group-text"><i data-feather="user"></i></span>
                    <input type="text" class="form-control" id="login-username" required>
                  </div>
                  <div class="form-text">Default: admin / user</div>
                </div>
                <div class="mb-3">
                  <label for="login-password" class="form-label">Password</label>
                  <div class="input-group">
                    <span class="input-group-text"><i data-feather="lock"></i></span>
                    <input type="password" class="form-control" id="login-password" required>
                    <button class="btn btn-outline-secondary" type="button" id="toggle-password">
                      <i data-feather="eye"></i>
                    </button>
                  </div>
                  <div class="form-text">Default: admin123 / user123</div>
                </div>
                <div id="login-error" class="alert alert-danger d-none"></div>
              </form>
            </div>
            <div class="modal-footer">
              <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
              <button type="button" class="btn btn-primary" onclick="auth.login()">
                <i data-feather="log-in" class="me-1"></i> Login
              </button>
            </div>
          </div>
        </div>
      </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', modalHtml);
    loginModal = document.getElementById('login-modal');
    
    // Add event listener for password toggle
    const togglePassword = document.getElementById('toggle-password');
    if (togglePassword) {
      togglePassword.addEventListener('click', function() {
        const passwordInput = document.getElementById('login-password');
        const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordInput.setAttribute('type', type);
        
        // Toggle icon
        const icon = this.querySelector('i');
        if (type === 'password') {
          icon.setAttribute('data-feather', 'eye');
        } else {
          icon.setAttribute('data-feather', 'eye-off');
        }
        
        feather.replace();
      });
    }
    
    // Add event listener for form submission
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
      loginForm.addEventListener('submit', function(event) {
        event.preventDefault();
        login();
      });
    }
  }
  
  // Show the modal
  const modal = new bootstrap.Modal(loginModal);
  modal.show();
  
  // Initialize feather icons
  feather.replace();
}

/**
 * Login function
 */
function login() {
  const username = document.getElementById('login-username').value;
  const password = document.getElementById('login-password').value;
  const errorElement = document.getElementById('login-error');
  
  if (!username || !password) {
    errorElement.textContent = 'Please enter both username and password';
    errorElement.classList.remove('d-none');
    return;
  }
  
  // Clear previous errors
  errorElement.classList.add('d-none');
  
  // Show loading indicator
  const loginButton = document.querySelector('#login-modal .btn-primary');
  const originalText = loginButton.innerHTML;
  loginButton.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span> Logging in...';
  loginButton.disabled = true;
  
  // Send login request
  fetch('/api/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      username: username,
      password: password
    })
  })
  .then(response => response.json())
  .then(data => {
    // Reset button
    loginButton.innerHTML = originalText;
    loginButton.disabled = false;
    
    if (data.status === 'success') {
      // Store token
      authToken = data.data.token;
      localStorage.setItem('auth_token', authToken);
      
      // Update UI
      updateAuthUI(true, data.data.user);
      
      // Close modal
      const loginModal = document.getElementById('login-modal');
      const modal = bootstrap.Modal.getInstance(loginModal);
      modal.hide();
      
      // Show success message
      ui.showToast('Login successful', 'success');
      
      // Refresh data
      core.checkSystemStatus();
      tasks.loadScheduledTasks();
    } else {
      // Show error
      errorElement.textContent = data.message || 'Login failed';
      errorElement.classList.remove('d-none');
      
      // Shake animation for error
      const modalContent = document.querySelector('.modal-content');
      modalContent.classList.add('shake-animation');
      setTimeout(() => {
        modalContent.classList.remove('shake-animation');
      }, 500);
    }
  })
  .catch(error => {
    console.error('Login error:', error);
    errorElement.textContent = 'An error occurred during login';
    errorElement.classList.remove('d-none');
    
    // Reset button
    loginButton.innerHTML = originalText;
    loginButton.disabled = false;
  });
}

/**
 * Logout function
 */
function logout() {
  // Clear token
  localStorage.removeItem('auth_token');
  authToken = null;
  
  // Update UI
  updateAuthUI(false);
  
  // Show message
  ui.showToast('Logged out successfully', 'info');
}

/**
 * Get current auth token
 */
function getAuthToken() {
  return authToken;
}

// Export module functions
export default {
  checkAuthStatus,
  updateAuthUI,
  showLoginModal,
  login,
  logout,
  getAuthToken
};
