"""
Main orchestration script for the Mini SOC Automation Tool.
"""
import argparse
import time
from logger import get_logger
from log_parser import extract_unique_ips
from reputation_checker import ReputationChecker
from scoring_engine import calculate_risk
from report_generator import generate_reports

logger = get_logger("Main")

def main():
    parser = argparse.ArgumentParser(description="Mini SOC Automation Tool")
    parser.add_argument("logfile", help="Path to the firewall log CSV file")
    args = parser.parse_args()

    start_time = time.time()
    logger.info("Starting Mini SOC Analysis...")

    # Step 1: Parse Logs
    try:
        ips_to_check = extract_unique_ips(args.logfile)
    except Exception as e:
        logger.critical("Failed to parse logs. Exiting.")
        return

    if not ips_to_check:
        logger.info("No valid public IPs found in the log file. Exiting.")
        return

    # Step 2: Initialize Reputation Checker
    checker = ReputationChecker()
    results = []
    high_risk_count = 0

    # Step 3 & 4: Query APIs and Calculate Score
    logger.info(f"Querying TI APIs for {len(ips_to_check)} IPs...")
    for ip in ips_to_check:
        logger.info(f"Analyzing IP: {ip}")
        
        abuse_data = checker.check_abuseipdb(ip)
        vt_data = checker.check_virustotal(ip)
        
        analysis = calculate_risk(abuse_data, vt_data)
        
        result_entry = {
            "ip": ip,
            **analysis
        }
        results.append(result_entry)
        
        if analysis['verdict'] in ['High', 'Critical']:
            logger.warning(f"FLAGGED IP: {ip} | Verdict: {analysis['verdict']} | Score: {analysis['risk_score']}")
            high_risk_count += 1
            
        # Add a small sleep to avoid hitting strict free-tier rate limits instantly
        time.sleep(0.5) 

    # Step 5: Generate Reports
    generate_reports(results)

    # Step 6: Execution Summary
    exec_time = round(time.time() - start_time, 2)
    print("\n" + "="*40)
    print("📊 MINI SOC EXECUTION SUMMARY")
    print("="*40)
    print(f"Total IPs Processed : {len(ips_to_check)}")
    print(f"High/Critical IPs   : {high_risk_count}")
    print(f"Execution Time      : {exec_time} seconds")
    print(f"Log File            : soc.log")
    print(f"JSON Report         : full_report.json")
    print(f"CSV Report          : flagged_ips.csv")
    print("="*40 + "\n")

if __name__ == "__main__":
    main()
    
    