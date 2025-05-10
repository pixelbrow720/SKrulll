"""
Routes for the web application.
Defines all URL routes and their handlers.
"""

import json
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, g, current_app, session, abort
from web.auth import token_required, admin_required, api_key_required, rate_limit, validate_csrf
from web.utils import (
    format_error_response, format_success_response, validate_json_request,
    log_api_call, generate_csrf_token, generate_unique_id, get_client_ip
)
from web.schemas import (
    TaskCreate, TaskUpdate, TaskStatusRequest, UserCreate, UserLogin,
    ScanConfigCreate, ScanConfigUpdate, ReportCreate
)


# Create blueprints
main_bp = Blueprint('main', __name__)
api_bp = Blueprint('api', __name__)


# Main routes (HTML pages)
@main_bp.route('/')
def index():
    """Render the index page"""
    return render_template('index.html')


@main_bp.route('/dashboard')
def dashboard():
    """Render the dashboard page"""
    # In a real app, you'd check if the user is authenticated
    # and redirect to login if not
    
    # Generate CSRF token for forms
    csrf_token = generate_csrf_token()
    
    # Get modules for the module selector
    modules = [
        {'id': 'osint.domain_recon', 'name': 'Domain Reconnaissance'},
        {'id': 'osint.social_analyzer', 'name': 'Social Media Analysis'},
        {'id': 'scanner.domain', 'name': 'Domain Scanner'},
        {'id': 'scanner.metadata', 'name': 'Metadata Extractor'},
        {'id': 'scanner.netmap', 'name': 'Network Mapper'},
        {'id': 'security.attack_vector_mapper', 'name': 'Attack Vector Mapper'},
        {'id': 'security.code_analyzer', 'name': 'Code Security Analyzer'},
        {'id': 'security.data_leak_detector', 'name': 'Data Leak Detector'},
        {'id': 'security.entry_point_analyzer', 'name': 'Entry Point Analyzer'},
        {'id': 'security.network_mapper', 'name': 'Network Security Mapper'},
        {'id': 'security.port_scanner', 'name': 'Port Scanner'},
        {'id': 'security.service_enumerator', 'name': 'Service Enumerator'},
        {'id': 'security.vulnerability_scanner', 'name': 'Vulnerability Scanner'},
        {'id': 'vulnerability.api_tester', 'name': 'API Security Tester'},
        {'id': 'vulnerability.exploiter', 'name': 'Exploit Tester'},
        {'id': 'vulnerability.scanner', 'name': 'Vulnerability Scanner'}
    ]
    
    # Get recent tasks (in a real app, you'd fetch these from a database)
    recent_tasks = [
        {
            'id': '1',
            'name': 'Domain Scan - example.com',
            'module': 'scanner.domain',
            'status': 'completed',
            'created_at': datetime(2025, 5, 10, 8, 30, 0),
            'completed_at': datetime(2025, 5, 10, 8, 35, 0)
        },
        {
            'id': '2',
            'name': 'Network Scan - 192.168.1.0/24',
            'module': 'security.network_mapper',
            'status': 'running',
            'created_at': datetime(2025, 5, 10, 9, 0, 0),
            'progress': 65
        },
        {
            'id': '3',
            'name': 'Vulnerability Scan - api.example.com',
            'module': 'vulnerability.scanner',
            'status': 'scheduled',
            'created_at': datetime(2025, 5, 10, 9, 15, 0)
        }
    ]
    
    # Get system status (in a real app, you'd fetch this from a monitoring system)
    system_status = {
        'cpu_usage': 32,
        'memory_usage': 45,
        'disk_usage': 28,
        'active_tasks': 1,
        'queued_tasks': 2,
        'services': [
            {'name': 'API Server', 'status': 'connected'},
            {'name': 'Database', 'status': 'connected'},
            {'name': 'Task Scheduler', 'status': 'connected'},
            {'name': 'Scanner Engine', 'status': 'connected'}
        ]
    }
    
    return render_template(
        'dashboard.html',
        csrf_token=csrf_token,
        modules=modules,
        recent_tasks=recent_tasks,
        system_status=system_status
    )


@main_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login"""
    if request.method == 'POST':
        # In a real app, you'd validate credentials and set up a session
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Mock login logic (replace with real authentication)
        if username == 'admin' and password == 'password':
            session['user_id'] = '1'
            session['is_admin'] = True
            return redirect(url_for('main.dashboard'))
        else:
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')


@main_bp.route('/logout')
def logout():
    """Handle user logout"""
    # Clear session
    session.clear()
    return redirect(url_for('main.index'))


# API routes
@api_bp.route('/health')
def health_check():
    """API health check endpoint"""
    return jsonify({
        'status': 'success',
        'message': 'API is operational',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    })


@api_bp.route('/tasks', methods=['GET'])
@api_key_required
@log_api_call
def get_tasks():
    """Get all tasks for the current user"""
    # In a real app, you'd fetch tasks from a database
    # For now, we'll return mock data
    
    # Get query parameters for filtering
    module = request.args.get('module')
    status = request.args.get('status')
    
    # Mock tasks data
    tasks = [
        {
            'id': '1',
            'name': 'Domain Scan - example.com',
            'description': 'Comprehensive domain scan',
            'module': 'scanner.domain',
            'target': 'example.com',
            'status': 'completed',
            'created_at': '2025-05-10T08:30:00Z',
            'completed_at': '2025-05-10T08:35:00Z',
            'result': {
                'vulnerabilities': 0,
                'information': 12
            }
        },
        {
            'id': '2',
            'name': 'Network Scan - 192.168.1.0/24',
            'description': 'Internal network scan',
            'module': 'security.network_mapper',
            'target': '192.168.1.0/24',
            'status': 'running',
            'created_at': '2025-05-10T09:00:00Z',
            'progress': 65
        },
        {
            'id': '3',
            'name': 'Vulnerability Scan - api.example.com',
            'description': 'API security assessment',
            'module': 'vulnerability.scanner',
            'target': 'api.example.com',
            'status': 'scheduled',
            'created_at': '2025-05-10T09:15:00Z'
        }
    ]
    
    # Apply filters if provided
    if module:
        tasks = [task for task in tasks if task['module'] == module]
    
    if status:
        tasks = [task for task in tasks if task['status'] == status]
    
    return format_success_response(
        message="Tasks retrieved successfully",
        data={"tasks": tasks, "count": len(tasks)}
    )


@api_bp.route('/tasks', methods=['POST'])
@api_key_required
@validate_csrf
@validate_json_request(TaskCreate)
@log_api_call
def create_task():
    """Create a new task"""
    # Get validated data from the request
    task_data = g.validated_data
    
    # In a real app, you'd save the task to a database
    # For now, we'll just return a success response with mock data
    
    # Generate a unique ID for the task
    task_id = generate_unique_id()
    
    # Create task object
    task = {
        'id': task_id,
        'name': task_data.name,
        'description': task_data.description,
        'module': task_data.module,
        'target': task_data.target,
        'options': task_data.options,
        'priority': task_data.priority,
        'tags': task_data.tags,
        'status': 'scheduled',
        'created_at': datetime.utcnow().isoformat(),
        'created_by': g.user_id
    }
    
    # Log task creation
    current_app.logger.info(f"Task created: {task_id} - {task_data.name}")
    
    return format_success_response(
        message="Task created successfully",
        data={"task": task}
    )


@api_bp.route('/tasks/<task_id>', methods=['GET'])
@api_key_required
@log_api_call
def get_task(task_id):
    """Get a specific task by ID"""
    # In a real app, you'd fetch the task from a database
    # For now, we'll return mock data based on the task ID
    
    # Mock task data
    if task_id == '1':
        task = {
            'id': '1',
            'name': 'Domain Scan - example.com',
            'description': 'Comprehensive domain scan',
            'module': 'scanner.domain',
            'target': 'example.com',
            'status': 'completed',
            'created_at': '2025-05-10T08:30:00Z',
            'completed_at': '2025-05-10T08:35:00Z',
            'result': {
                'vulnerabilities': 0,
                'information': 12,
                'details': [
                    {'type': 'info', 'message': 'Domain registered on 2010-01-15'},
                    {'type': 'info', 'message': 'WHOIS privacy protection enabled'},
                    {'type': 'info', 'message': 'DNS records found: A, MX, TXT, CNAME'}
                ]
            }
        }
    elif task_id == '2':
        task = {
            'id': '2',
            'name': 'Network Scan - 192.168.1.0/24',
            'description': 'Internal network scan',
            'module': 'security.network_mapper',
            'target': '192.168.1.0/24',
            'status': 'running',
            'created_at': '2025-05-10T09:00:00Z',
            'progress': 65,
            'result': {
                'hosts_found': 12,
                'hosts_scanned': 8,
                'details': [
                    {'ip': '192.168.1.1', 'status': 'up', 'hostname': 'router.local'},
                    {'ip': '192.168.1.2', 'status': 'up', 'hostname': 'server.local'},
                    {'ip': '192.168.1.5', 'status': 'up', 'hostname': 'desktop.local'}
                ]
            }
        }
    elif task_id == '3':
        task = {
            'id': '3',
            'name': 'Vulnerability Scan - api.example.com',
            'description': 'API security assessment',
            'module': 'vulnerability.scanner',
            'target': 'api.example.com',
            'status': 'scheduled',
            'created_at': '2025-05-10T09:15:00Z'
        }
    else:
        return format_error_response(
            message="Task not found",
            code=404,
            details={"task_id": task_id}
        )
    
    return format_success_response(
        message="Task retrieved successfully",
        data={"task": task}
    )


@api_bp.route('/tasks/<task_id>', methods=['PUT'])
@api_key_required
@validate_csrf
@validate_json_request(TaskUpdate)
@log_api_call
def update_task(task_id):
    """Update a specific task by ID"""
    # Get validated data from the request
    task_data = g.validated_data
    
    # In a real app, you'd update the task in a database
    # For now, we'll just return a success response with mock data
    
    # Check if task exists
    if task_id not in ['1', '2', '3']:
        return format_error_response(
            message="Task not found",
            code=404,
            details={"task_id": task_id}
        )
    
    # Create updated task object (in a real app, you'd merge with existing data)
    task = {
        'id': task_id,
        'name': task_data.name if task_data.name is not None else f"Task {task_id}",
        'description': task_data.description,
        'status': task_data.status if task_data.status is not None else 'scheduled',
        'updated_at': datetime.utcnow().isoformat()
    }
    
    # Log task update
    current_app.logger.info(f"Task updated: {task_id}")
    
    return format_success_response(
        message="Task updated successfully",
        data={"task": task}
    )


@api_bp.route('/tasks/<task_id>', methods=['DELETE'])
@api_key_required
@validate_csrf
@log_api_call
def delete_task(task_id):
    """Delete a specific task by ID"""
    # In a real app, you'd delete the task from a database
    # For now, we'll just return a success response
    
    # Check if task exists
    if task_id not in ['1', '2', '3']:
        return format_error_response(
            message="Task not found",
            code=404,
            details={"task_id": task_id}
        )
    
    # Log task deletion
    current_app.logger.info(f"Task deleted: {task_id}")
    
    return format_success_response(
        message="Task deleted successfully"
    )


@api_bp.route('/tasks/status', methods=['POST'])
@api_key_required
@validate_json_request(TaskStatusRequest)
@log_api_call
def get_task_status():
    """Get status for multiple tasks"""
    # Get validated data from the request
    task_data = g.validated_data
    
    # In a real app, you'd fetch task statuses from a database
    # For now, we'll return mock data based on the task IDs
    
    # Mock task status data
    task_statuses = []
    for task_id in task_data.task_ids:
        if task_id == '1':
            task_statuses.append({
                'id': '1',
                'status': 'completed',
                'progress': 100,
                'updated_at': '2025-05-10T08:35:00Z'
            })
        elif task_id == '2':
            task_statuses.append({
                'id': '2',
                'status': 'running',
                'progress': 65,
                'updated_at': '2025-05-10T09:10:00Z'
            })
        elif task_id == '3':
            task_statuses.append({
                'id': '3',
                'status': 'scheduled',
                'progress': 0,
                'updated_at': '2025-05-10T09:15:00Z'
            })
    
    return format_success_response(
        message="Task statuses retrieved successfully",
        data={"tasks": task_statuses}
    )


@api_bp.route('/users', methods=['POST'])
@admin_required
@validate_csrf
@validate_json_request(UserCreate)
@log_api_call
def create_user():
    """Create a new user (admin only)"""
    # Get validated data from the request
    user_data = g.validated_data
    
    # In a real app, you'd save the user to a database
    # For now, we'll just return a success response with mock data
    
    # Generate a unique ID for the user
    user_id = generate_unique_id()
    
    # Create user object (excluding password)
    user = {
        'id': user_id,
        'username': user_data.username,
        'email': user_data.email,
        'is_active': True,
        'is_admin': False,
        'created_at': datetime.utcnow().isoformat()
    }
    
    # Log user creation
    current_app.logger.info(f"User created: {user_id} - {user_data.username}")
    
    return format_success_response(
        message="User created successfully",
        data={"user": user}
    )


@api_bp.route('/auth/login', methods=['POST'])
@validate_json_request(UserLogin)
@rate_limit(limit=5, per=60)  # Limit login attempts
@log_api_call
def login_api():
    """API login endpoint"""
    # Get validated data from the request
    login_data = g.validated_data
    
    # In a real app, you'd validate credentials against a database
    # For now, we'll use mock data
    
    # Mock login logic
    if login_data.username == 'admin' and login_data.password == 'password':
        # Import here to avoid circular imports
        from web.auth import generate_token, generate_refresh_token
        
        # Generate tokens
        access_token = generate_token('1', is_admin=True)
        refresh_token = generate_refresh_token('1')
        
        # Log successful login
        current_app.logger.info(f"User logged in: {login_data.username} from {get_client_ip()}")
        
        return format_success_response(
            message="Login successful",
            data={
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "Bearer",
                "expires_in": 24 * 60 * 60  # 24 hours in seconds
            }
        )
    else:
        # Log failed login attempt
        current_app.logger.warning(f"Failed login attempt: {login_data.username} from {get_client_ip()}")
        
        return format_error_response(
            message="Invalid credentials",
            code=401
        )


@api_bp.route('/auth/refresh', methods=['POST'])
@log_api_call
def refresh_token():
    """Refresh access token using refresh token"""
    # Get refresh token from request
    refresh_token = request.json.get('refresh_token')
    
    if not refresh_token:
        return format_error_response(
            message="Refresh token is required",
            code=400
        )
    
    # In a real app, you'd validate the refresh token
    # For now, we'll use mock logic
    
    # Import here to avoid circular imports
    from web.auth import decode_token, generate_token
    
    # Decode refresh token
    payload = decode_token(refresh_token)
    
    if 'error' in payload:
        return format_error_response(
            message=payload['error'],
            code=401
        )
    
    # Generate new access token
    user_id = payload['sub']
    is_admin = payload.get('admin', False)
    access_token = generate_token(user_id, is_admin)
    
    return format_success_response(
        message="Token refreshed successfully",
        data={
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 24 * 60 * 60  # 24 hours in seconds
        }
    )


@api_bp.route('/modules', methods=['GET'])
@api_key_required
@log_api_call
def get_modules():
    """Get available modules"""
    # In a real app, you'd fetch modules from a registry or database
    # For now, we'll return mock data
    
    modules = [
        {
            'id': 'osint.domain_recon',
            'name': 'Domain Reconnaissance',
            'description': 'Gather information about a domain',
            'category': 'OSINT',
            'options': {
                'whois': {'type': 'boolean', 'default': True, 'description': 'Perform WHOIS lookup'},
                'dns': {'type': 'boolean', 'default': True, 'description': 'Perform DNS lookups'},
                'subdomains': {'type': 'boolean', 'default': True, 'description': 'Discover subdomains'}
            }
        },
        {
            'id': 'security.port_scanner',
            'name': 'Port Scanner',
            'description': 'Scan for open ports on a target',
            'category': 'Security',
            'options': {
                'ports': {'type': 'string', 'default': '1-1000', 'description': 'Port range to scan'},
                'timeout': {'type': 'integer', 'default': 5, 'description': 'Timeout in seconds'},
                'scan_type': {'type': 'string', 'default': 'SYN', 'enum': ['SYN', 'CONNECT', 'FIN'], 'description': 'Scan type'}
            }
        },
        {
            'id': 'vulnerability.scanner',
            'name': 'Vulnerability Scanner',
            'description': 'Scan for vulnerabilities on a target',
            'category': 'Vulnerability',
            'options': {
                'intensity': {'type': 'string', 'default': 'medium', 'enum': ['low', 'medium', 'high'], 'description': 'Scan intensity'},
                'categories': {'type': 'array', 'default': ['web', 'network'], 'description': 'Vulnerability categories to scan for'}
            }
        }
    ]
    
    return format_success_response(
        message="Modules retrieved successfully",
        data={"modules": modules, "count": len(modules)}
    )


@api_bp.route('/scan-configs', methods=['POST'])
@api_key_required
@validate_csrf
@validate_json_request(ScanConfigCreate)
@log_api_call
def create_scan_config():
    """Create a new scan configuration"""
    # Get validated data from the request
    config_data = g.validated_data
    
    # In a real app, you'd save the config to a database
    # For now, we'll just return a success response with mock data
    
    # Generate a unique ID for the config
    config_id = generate_unique_id()
    
    # Create config object
    config = {
        'id': config_id,
        'name': config_data.name,
        'description': config_data.description,
        'modules': config_data.modules,
        'options': config_data.options,
        'is_default': config_data.is_default,
        'created_at': datetime.utcnow().isoformat(),
        'created_by': g.user_id
    }
    
    # Log config creation
    current_app.logger.info(f"Scan config created: {config_id} - {config_data.name}")
    
    return format_success_response(
        message="Scan configuration created successfully",
        data={"config": config}
    )


@api_bp.route('/reports', methods=['POST'])
@api_key_required
@validate_csrf
@validate_json_request(ReportCreate)
@log_api_call
def create_report():
    """Create a new report from task results"""
    # Get validated data from the request
    report_data = g.validated_data
    
    # In a real app, you'd generate the report and save it
    # For now, we'll just return a success response with mock data
    
    # Generate a unique ID for the report
    report_id = generate_unique_id()
    
    # Create report object
    report = {
        'id': report_id,
        'title': report_data.title,
        'description': report_data.description,
        'task_ids': report_data.task_ids,
        'format': report_data.format,
        'status': 'generating',
        'created_at': datetime.utcnow().isoformat(),
        'created_by': g.user_id
    }
    
    # Log report creation
    current_app.logger.info(f"Report creation started: {report_id} - {report_data.title}")
    
    return format_success_response(
        message="Report generation started",
        data={"report": report}
    )


@api_bp.route('/system/status', methods=['GET'])
@api_key_required
@log_api_call
def get_system_status():
    """Get system status information"""
    # In a real app, you'd fetch this from a monitoring system
    # For now, we'll return mock data
    
    status = {
        'cpu_usage': 32,
        'memory_usage': 45,
        'disk_usage': 28,
        'active_tasks': 1,
        'queued_tasks': 2,
        'uptime': 86400,  # 1 day in seconds
        'services': [
            {'name': 'API Server', 'status': 'connected', 'uptime': 86400},
            {'name': 'Database', 'status': 'connected', 'uptime': 86400},
            {'name': 'Task Scheduler', 'status': 'connected', 'uptime': 86400},
            {'name': 'Scanner Engine', 'status': 'connected', 'uptime': 86400}
        ],
        'timestamp': datetime.utcnow().isoformat()
    }
    
    return format_success_response(
        message="System status retrieved successfully",
        data={"status": status}
    )
