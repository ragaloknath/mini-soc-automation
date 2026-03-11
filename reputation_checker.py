"""Module to interact with Threat Intelligence APIs."""
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Dict, Any
from config import (
    ABUSEIPDB_API_KEY, ABUSEIPDB_URL, 
    VIRUSTOTAL_API_KEY, VIRUSTOTAL_URL,
    MAX_RETRIES, BACKOFF_FACTOR, TIMEOUT
)
from logger import get_logger

logger = get_logger(__name__)
print("AbuseIPDB Key:", ABUSEIPDB_API_KEY)

class ReputationChecker:
    """Handles API queries to Threat Intelligence providers."""
    
    def __init__(self):
        if not ABUSEIPDB_API_KEY or not VIRUSTOTAL_API_KEY:
            logger.warning("One or more API keys are missing. Checks may fail or return 0.")
            
        # Configure robust session with exponential backoff for rate limits
        self.session = requests.Session()
        retry_strategy = Retry(
            total=MAX_RETRIES,
            backoff_factor=BACKOFF_FACTOR,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)

    def check_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Queries AbuseIPDB for a given IP."""
        if not ABUSEIPDB_API_KEY:
            return {"error": "Missing API Key", "score": 0}
            
        headers = {
            'Accept': 'application/json',
            'Key': ABUSEIPDB_API_KEY
        }
        params = {'ipAddress': ip, 'maxAgeInDays': '90'}
        
        try:
            response = self.session.get(
                ABUSEIPDB_URL, headers=headers, params=params, timeout=TIMEOUT
            )
            response.raise_for_status()
            data = response.json()
            print("AbuseIPDB RAW:", data)
            return {"score": data['data'].get('abuseConfidenceScore', 0)}
        except Exception as e:
            logger.error(f"AbuseIPDB error for IP {ip}: {str(e)}")
            return {"error": str(e), "score": 0}

    def check_virustotal(self, ip: str) -> Dict[str, Any]:
        """Queries VirusTotal for a given IP."""
        if not VIRUSTOTAL_API_KEY:
            return {"error": "Missing API Key", "malicious_count": 0}
            
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY
        }
        
        try:
            response = self.session.get(
                VIRUSTOTAL_URL.format(ip), headers=headers, timeout=TIMEOUT
            )
            response.raise_for_status()
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return {"malicious_count": stats.get('malicious', 0)}
        except Exception as e:
            logger.error(f"VirusTotal error for IP {ip}: {str(e)}")
            return {"error": str(e), "malicious_count": 0}