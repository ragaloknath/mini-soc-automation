"""Module for parsing firewall logs and extracting IPs."""
import csv
from typing import Set
from utils import is_valid_public_ip
from logger import get_logger

logger = get_logger(__name__)

def extract_unique_ips(filepath: str) -> Set[str]:
    """
    Reads a CSV firewall log and extracts unique, valid public source IPs.
    
    Args:
        filepath (str): Path to the firewall log CSV.
        
    Returns:
        Set[str]: A set of unique public IP addresses.
    """
    unique_ips = set()
    try:
        with open(filepath, mode='r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                source_ip = row.get('source_ip', '').strip()
                if source_ip and is_valid_public_ip(source_ip):
                    unique_ips.add(source_ip)
                    
        logger.info(f"Extracted {len(unique_ips)} unique public IPs from {filepath}")
        return unique_ips
        
    except FileNotFoundError:
        logger.error(f"Log file not found: {filepath}")
        raise
    except Exception as e:
        logger.error(f"Error parsing log file {filepath}: {str(e)}")
        raise