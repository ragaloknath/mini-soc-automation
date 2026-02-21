"""Module to generate JSON and CSV reports."""
import json
import csv
from typing import List, Dict, Any
from config import OUTPUT_JSON, OUTPUT_CSV
from logger import get_logger

logger = get_logger(__name__)

def generate_reports(results: List[Dict[str, Any]]) -> None:
    """
    Writes analysis results to JSON and CSV formats.
    
    Args:
        results (List[Dict]): The correlated results for all parsed IPs.
    """
    # 1. Generate JSON Report (Full details)
    try:
        with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4)
        logger.info(f"Successfully generated full report: {OUTPUT_JSON}")
    except Exception as e:
        logger.error(f"Failed to write JSON report: {str(e)}")

    # 2. Generate CSV Report (Flagged IPs only - High/Critical)
    flagged_ips = [res for res in results if res['verdict'] in ['High', 'Critical']]
    
    try:
        with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'AbuseIPDB_Score', 'VirusTotal_Malicious', 'Risk_Score', 'Verdict'])
            
            for item in flagged_ips:
                writer.writerow([
                    item['ip'],
                    item['abuse_score'],
                    item['vt_malicious'],
                    item['risk_score'],
                    item['verdict']
                ])
        logger.info(f"Successfully generated flagged IPs report: {OUTPUT_CSV}")
    except Exception as e:
        logger.error(f"Failed to write CSV report: {str(e)}")