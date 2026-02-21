"""Utility functions for IP validation and general helpers."""
import ipaddress
from logger import get_logger

logger = get_logger(__name__)

def is_valid_public_ip(ip_str: str) -> bool:
    """
    Validates if a string is a properly formatted public IP address.
    
    Args:
        ip_str (str): The IP string to validate.
        
    Returns:
        bool: True if valid public IP, False otherwise.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        # We ignore private, loopback, and multicast IPs for external API checking
        if ip.is_private or ip.is_loopback or ip.is_multicast:
            logger.debug(f"IP {ip_str} is valid but not public. Skipping external check.")
            return False
        return True
    except ValueError:
        logger.warning(f"Invalid IP address format encountered: {ip_str}")
        return False