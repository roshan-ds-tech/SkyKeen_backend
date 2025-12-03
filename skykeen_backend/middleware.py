"""
Custom middleware for request logging
"""
import sys
import time
import logging
from django.utils.deprecation import MiddlewareMixin

# Create our own logger
logger = logging.getLogger('skykeen_backend')


class RequestLoggingMiddleware(MiddlewareMixin):
    """
    Middleware to log all incoming requests to the console
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        # Force output on initialization to verify middleware is loaded
        sys.stdout.write("\n" + "="*60 + "\n")
        sys.stdout.write("RequestLoggingMiddleware LOADED\n")
        sys.stdout.write("="*60 + "\n")
        sys.stdout.flush()
        super().__init__(get_response)
    
    def process_request(self, request):
        request.start_time = time.time()
        # Log incoming request immediately
        log_msg = f"\n>>> INCOMING REQUEST: {request.method} {request.path}\n"
        sys.stdout.write(log_msg)
        sys.stdout.flush()
        return None
    
    def process_response(self, request, response):
        if hasattr(request, 'start_time'):
            duration = time.time() - request.start_time
        else:
            duration = 0.0
        
        # Log response - use multiple methods to ensure visibility
        log_message = f"<<< RESPONSE: {request.method} {request.path} - Status: {response.status_code} - Time: {duration:.3f}s\n"
        
        # Method 1: Direct stdout write
        sys.stdout.write(log_message)
        sys.stdout.flush()
        
        # Method 2: Direct stderr write
        sys.stderr.write(log_message)
        sys.stderr.flush()
        
        # Method 3: Print
        print(log_message, end='', flush=True)
        
        # Method 4: Logger
        try:
            logger.info(log_message.strip())
        except:
            pass
        
        return response

