"""
Streamlit Web Dashboard for the Mini SOC Automation Tool.
"""
import streamlit as st
import pandas as pd
import tempfile
import os
import time
from log_parser import extract_unique_ips
from reputation_checker import ReputationChecker
from scoring_engine import calculate_risk

# --- Page Configuration ---
st.set_page_config(page_title="Mini SOC Dashboard", page_icon="🛡️", layout="wide")

# --- UI Header ---
st.title("🛡️ Mini SOC Threat Intelligence Dashboard")
st.markdown("Upload your firewall logs to automatically extract, analyze, and score IP addresses.")

# --- Sidebar Configuration ---
st.sidebar.header("Configuration")
st.sidebar.info("Ensure your API keys are set in the .env file in your project folder.")

# --- Main App Logic ---
# 1. File Upload mechanism
uploaded_file = st.file_uploader("Upload Firewall Log (CSV)", type=["csv"])

if uploaded_file is not None:
    st.success("File uploaded successfully!")
    
    if st.button("Start SOC Analysis"):
        with st.spinner("Analyzing logs and querying Threat Intelligence APIs..."):
            
            # 2. Save uploaded file temporarily so log_parser can read it
            with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
                tmp.write(uploaded_file.getvalue())
                tmp_path = tmp.name

            # 3. Extract IPs using your existing logic
            try:
                ips_to_check = extract_unique_ips(tmp_path)
            except Exception as e:
                st.error(f"Error parsing logs: {e}")
                ips_to_check = []
            finally:
                os.remove(tmp_path) # Clean up temp file

            if not ips_to_check:
                st.warning("No valid public IPs found in the uploaded log.")
            else:
                st.info(f"Extracted {len(ips_to_check)} unique public IPs. Initiating TI checks...")
                
                # 4. Initialize Checker & Process
                checker = ReputationChecker()
                results = []
                
                # Progress bar for visual feedback
                progress_bar = st.progress(0)
                total_ips = len(ips_to_check)
                
                for i, ip in enumerate(ips_to_check):
                    # Query APIs
                    abuse_data = checker.check_abuseipdb(ip)
                    vt_data = checker.check_virustotal(ip)
                    
                    # Score the results
                    analysis = calculate_risk(abuse_data, vt_data)
                    
                    results.append({
                        "IP Address": ip,
                        "AbuseIPDB Score": analysis['abuse_score'],
                        "VirusTotal Engines": analysis['vt_malicious'],
                        "Risk Score": analysis['risk_score'],
                        "Verdict": analysis['verdict']
                    })
                    
                    # Update progress bar
                    progress_bar.progress((i + 1) / total_ips)
                    time.sleep(0.5) # Slight delay for free-tier API rate limits

                # --- 5. Display Results in Dashboard ---
                st.subheader("📊 Analysis Results")
                
                df = pd.DataFrame(results)
                
                # Top Level Metrics
                col1, col2, col3 = st.columns(3)
                col1.metric("Total IPs Analyzed", len(df))
                col2.metric("Critical/High Threats", len(df[df['Verdict'].isin(['Critical', 'High'])]))
                col3.metric("Clean IPs", len(df[df['Verdict'] == 'Low']))

                # Styled Data Table
                def color_verdict(val):
                    if val in ['Critical', 'High']:
                        color = '#ff4b4b' # Red
                    elif val == 'Medium':
                        color = '#ffa500' # Orange
                    else:
                        color = '#00cc66' # Green
                    return f'color: {color}; font-weight: bold'

                styled_df = df.style.map(color_verdict, subset=['Verdict'])
                st.dataframe(styled_df, use_container_width=True)

                # Visual Chart
                st.subheader("📈 Threat Distribution")
                verdict_counts = df['Verdict'].value_counts()
                st.bar_chart(verdict_counts)

                st.success("Analysis Complete!")