"""Configuration module for the Mini SOC Tool."""
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# API Keys
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# API Endpoints
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"

# File Paths
LOG_FILE = "soc.log"
OUTPUT_JSON = "full_report.json"
OUTPUT_CSV = "flagged_ips.csv"

# Configuration constants
MAX_RETRIES = 3
BACKOFF_FACTOR = 1.5
TIMEOUT = 10  # seconds