import os
import traceback
from flask import render_template

def register_error_handlers(app):
    """Register error handlers for the Flask app"""
    
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('error.html', 
            title="Page Not Found",
            heading="404 - Page Not Found",
            message="The page you're looking for doesn't exist.",
            icon="fa-map-signs",
            color="warning"
        ), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        # Log the error in production
        if not app.debug:
            error_traceback = traceback.format_exc()
            app.logger.error(f"500 error: {error_traceback}")
        
        return render_template('error.html', 
            title="Server Error",
            heading="500 - Server Error",
            message="Something went wrong on our end. Please try again later.",
            icon="fa-exclamation-triangle",
            color="danger",
            details=str(e) if app.debug else None
        ), 500
        
    @app.errorhandler(403)
    def forbidden(e):
        return render_template('error.html',
            title="Access Denied",
            heading="403 - Forbidden",
            message="You don't have permission to access this resource.",
            icon="fa-lock",
            color="danger"
        ), 403
        
    @app.errorhandler(401)
    def unauthorized(e):
        return render_template('error.html',
            title="Authentication Required",
            heading="401 - Unauthorized",
            message="You need to log in to access this resource.",
            icon="fa-user-lock",
            color="warning",
            back_url="/login",
            back_text="Go to Login"
        ), 401
        
    @app.errorhandler(405)
    def method_not_allowed(e):
        return render_template('error.html',
            title="Method Not Allowed",
            heading="405 - Method Not Allowed",
            message="The method is not allowed for the requested URL.",
            icon="fa-exclamation-circle",
            color="warning"
        ), 405
        
    @app.errorhandler(429)
    def too_many_requests(e):
        return render_template('error.html',
            title="Too Many Requests",
            heading="429 - Too Many Requests",
            message="You've sent too many requests. Please try again later.",
            icon="fa-hourglass-half",
            color="warning"
        ), 429 