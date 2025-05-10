"""
Main Flask application module.
Initializes and configures the Flask application.
"""

import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException
from web.schemas import ErrorResponse


def create_app(config=None):
    """
    Create and configure the Flask application
    
    Args:
        config: Configuration object or path to config file
        
    Returns:
        Flask application instance
    """
    app = Flask(__name__)
    
    # Load default configuration
    app.config.from_mapping(
        SECRET_KEY=os.environ.get('SECRET_KEY', 'dev_key_change_in_production'),
        DEBUG=os.environ.get('FLASK_DEBUG', 'False').lower() == 'true',
        TESTING=False,
        LOG_LEVEL=os.environ.get('LOG_LEVEL', 'INFO'),
        LOG_DIR=os.environ.get('LOG_DIR', 'logs'),
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16 MB max upload size
        PREFERRED_URL_SCHEME='https',
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=86400,  # 24 hours
        TEMPLATES_AUTO_RELOAD=True,
        JSON_SORT_KEYS=False,
        JSONIFY_PRETTYPRINT_REGULAR=False,
        JSON_AS_ASCII=False,
        TRAP_HTTP_EXCEPTIONS=True,
        PRESERVE_CONTEXT_ON_EXCEPTION=False,
        BOOTSTRAP_SERVE_LOCAL=True,
        # Default theme (dark or light)
        DEFAULT_THEME='dark'
    )
    
    # Load environment-specific configuration
    if config:
        if isinstance(config, str):
            app.config.from_pyfile(config)
        else:
            app.config.from_object(config)
    
    # Ensure log directory exists
    if not os.path.exists(app.config['LOG_DIR']):
        os.makedirs(app.config['LOG_DIR'])
    
    # Configure logging
    configure_logging(app)
    
    # Register error handlers
    register_error_handlers(app)
    
    # Register blueprints
    register_blueprints(app)
    
    # Register before request handlers
    @app.before_request
    def before_request():
        """Actions to perform before each request"""
        # Log request details in debug mode
        if app.debug:
            app.logger.debug(f"Request: {request.method} {request.path}")
    
    # Register after request handlers
    @app.after_request
    def after_request(response):
        """Actions to perform after each request"""
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Add CORS headers for API routes
        if request.path.startswith('/api/'):
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-API-Key, X-CSRF-Token'
        
        return response
    
    # Register context processors
    @app.context_processor
    def inject_globals():
        """Inject global variables into templates"""
        return {
            'app_name': 'SKrulll Dashboard',
            'app_version': '1.0.0',
            'default_theme': app.config['DEFAULT_THEME']
        }
    
    app.logger.info("Application initialized")
    return app


def configure_logging(app):
    """Configure application logging"""
    log_level = getattr(logging, app.config['LOG_LEVEL'].upper(), logging.INFO)
    
    # Configure root logger
    logging.basicConfig(level=log_level)
    
    # Create formatter
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    )
    
    # Create file handler for app.log
    file_handler = RotatingFileHandler(
        os.path.join(app.config['LOG_DIR'], 'app.log'),
        maxBytes=10485760,  # 10 MB
        backupCount=10
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)
    
    # Create file handler for errors.log (ERROR level and above)
    error_handler = RotatingFileHandler(
        os.path.join(app.config['LOG_DIR'], 'errors.log'),
        maxBytes=10485760,  # 10 MB
        backupCount=10
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(formatter)
    
    # Add handlers to app logger
    app.logger.addHandler(file_handler)
    app.logger.addHandler(error_handler)
    
    # Set app logger level
    app.logger.setLevel(log_level)


def register_error_handlers(app):
    """Register error handlers for the application"""
    
    @app.errorhandler(400)
    def bad_request(error):
        """Handle 400 Bad Request errors"""
        if request.path.startswith('/api/'):
            # API response
            error_response = ErrorResponse(
                message="Bad request",
                code=400,
                details={"error": str(error)}
            )
            return jsonify(error_response.dict()), 400
        else:
            # HTML response
            return render_template('400.html', error_message=str(error)), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        """Handle 401 Unauthorized errors"""
        if request.path.startswith('/api/'):
            # API response
            error_response = ErrorResponse(
                message="Unauthorized",
                code=401,
                details={"error": str(error)}
            )
            return jsonify(error_response.dict()), 401
        else:
            # HTML response
            return render_template('401.html', error_message=str(error)), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        """Handle 403 Forbidden errors"""
        if request.path.startswith('/api/'):
            # API response
            error_response = ErrorResponse(
                message="Forbidden",
                code=403,
                details={"error": str(error)}
            )
            return jsonify(error_response.dict()), 403
        else:
            # HTML response
            return render_template('403.html', error_message=str(error)), 403
    
    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 Not Found errors"""
        if request.path.startswith('/api/'):
            # API response
            error_response = ErrorResponse(
                message="Resource not found",
                code=404,
                details={"path": request.path}
            )
            return jsonify(error_response.dict()), 404
        else:
            # HTML response
            return render_template('404.html', error_message=str(error)), 404
    
    @app.errorhandler(405)
    def method_not_allowed(error):
        """Handle 405 Method Not Allowed errors"""
        if request.path.startswith('/api/'):
            # API response
            error_response = ErrorResponse(
                message="Method not allowed",
                code=405,
                details={
                    "method": request.method,
                    "allowed_methods": error.valid_methods
                }
            )
            return jsonify(error_response.dict()), 405
        else:
            # HTML response
            return render_template('405.html', error_message=str(error)), 405
    
    @app.errorhandler(429)
    def too_many_requests(error):
        """Handle 429 Too Many Requests errors"""
        if request.path.startswith('/api/'):
            # API response
            error_response = ErrorResponse(
                message="Too many requests",
                code=429,
                details={"error": str(error)}
            )
            return jsonify(error_response.dict()), 429
        else:
            # HTML response
            return render_template('429.html', error_message=str(error)), 429
    
    @app.errorhandler(500)
    def internal_server_error(error):
        """Handle 500 Internal Server Error errors"""
        app.logger.error(f"Internal Server Error: {str(error)}")
        
        if request.path.startswith('/api/'):
            # API response
            error_response = ErrorResponse(
                message="Internal server error",
                code=500
            )
            return jsonify(error_response.dict()), 500
        else:
            # HTML response
            return render_template('500.html'), 500
    
    @app.errorhandler(Exception)
    def handle_exception(error):
        """Handle all unhandled exceptions"""
        app.logger.exception("Unhandled exception")
        
        # If it's an HTTP exception, let the specific handler deal with it
        if isinstance(error, HTTPException):
            return app.handle_http_exception(error)
        
        if request.path.startswith('/api/'):
            # API response
            error_response = ErrorResponse(
                message="Internal server error",
                code=500
            )
            return jsonify(error_response.dict()), 500
        else:
            # HTML response
            return render_template('500.html'), 500


def register_blueprints(app):
    """Register blueprints with the application"""
    # Import blueprints
    from web.routes import main_bp, api_bp
    
    # Register blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix='/api')


# Create application instance
app = create_app()

if __name__ == '__main__':
    # Run the application
    app.run(host='0.0.0.0', port=5000)
