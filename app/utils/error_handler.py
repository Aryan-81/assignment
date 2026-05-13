import socket
import ssl
from typing import Any, Dict, Optional, Tuple

class ScanException(Exception):
    """Custom exception for certificate scanning errors."""
    def __init__(self, message: str, host: Optional[Any] = None):
        self.message = message
        self.host = host
        super().__init__(self.message)

def handle_scan_error(exc: Exception, raise_exc: bool = False) -> Tuple[bool, str]:
    """
    Uniformly handle errors during certificate scanning and return a success flag and error message.
    If raise_exc is True, it raises ScanException instead of returning a tuple.
    """
    error_msg = ""
    if isinstance(exc, socket.timeout):
        error_msg = "Connection timed out. The host might be unreachable."
    
    elif isinstance(exc, socket.gaierror):
        error_msg = "DNS resolution failed. Please check the hostname."
    
    elif isinstance(exc, ConnectionRefusedError):
        error_msg = "Connection refused. The host might not be listening on the specified port."
    
    elif isinstance(exc, ssl.SSLCertVerificationError):
        error_msg = f"SSL Certificate Verification failed: {exc.reason}"
    
    elif isinstance(exc, ssl.SSLError):
        error_msg = f"SSL Error: {str(exc)}"
    
    elif isinstance(exc, ValueError):
        error_msg = str(exc)
    
    else:
        # Generic fallback
        error_msg = f"An unexpected error occurred: {str(exc)}"

    if raise_exc:
        raise ScanException(error_msg)
    
    return False, error_msg

def format_error_response(error_msg: str, host: Optional[Any] = None) -> Dict[str, Any]:
    """
    Format a uniform error response for the API.
    """
    return {
        "success": False,
        "error": error_msg,
        "host": host,
        "certificate": None,
        "cached": False
    }

def format_success_response(host: Any, certificate: Any, cached: bool = False) -> Dict[str, Any]:
    """
    Format a uniform success response for the API.
    """
    return {
        "success": True,
        "error": None,
        "host": host,
        "certificate": certificate,
        "cached": cached
    }
