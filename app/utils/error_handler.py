from typing import Any, Dict, Optional, Tuple
import ssl
import socket

def handle_scan_error(exc: Exception) -> Tuple[bool, str]:
    """
    Uniformly handle errors during certificate scanning and return a success flag and error message.
    """
    if isinstance(exc, socket.timeout):
        return False, "Connection timed out. The host might be unreachable."
    
    if isinstance(exc, socket.gaierror):
        return False, "DNS resolution failed. Please check the hostname."
    
    if isinstance(exc, ConnectionRefusedError):
        return False, "Connection refused. The host might not be listening on the specified port."
    
    if isinstance(exc, ssl.SSLCertVerificationError):
        return False, f"SSL Certificate Verification failed: {exc.reason}"
    
    if isinstance(exc, ssl.SSLError):
        return False, f"SSL Error: {str(exc)}"
    
    if isinstance(exc, ValueError):
        return False, str(exc)
    
    # Generic fallback
    return False, f"An unexpected error occurred: {str(exc)}"

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
