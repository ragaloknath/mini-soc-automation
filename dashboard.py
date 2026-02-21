import os
import time
import tempfile
import pandas as pd
import streamlit as st
from dotenv import load_dotenv
# We changed this import to Google Gemini
from langchain_google_genai import ChatGoogleGenerativeAI 
from log_parser import extract_unique_ips
from reputation_checker import ReputationChecker
from scoring_engine import calculate_risk

# --- 1. AI Configuration & Setup ---
load_dotenv()  

# Initialize Gemini (This is the free alternative)
llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash")

def analyze_security_event(log_summary):
    """Sends aggregated log data to the AI Agent for forensic analysis."""
    prompt = f"""
    You are a Senior SOC Analyst. Analyze the following threat intelligence report:
    
    {log_summary}
    
    Based on these findings, please provide:
    1. A summary of the most critical threats detected.
    2. An assessment of whether this looks like a coordinated attack.
    3. Three technical mitigation steps for the admin.
    """
    response = llm.invoke(prompt)
    return response.content

# --- 2. Session State (Memory) Initialization ---
# This prevents the page from "forgetting" results when you click the AI button
if 'analysis_results' not in st.session_state:
    st.session_state['analysis_results'] = None

# --- 3. Page Configuration ---
st.set_page_config(page_title="Mini SOC Dashboard", page_icon="🛡️", layout="wide")

# --- 4. UI Header ---
st.title("🛡️ Mini SOC Threat Intelligence Dashboard")
st.markdown("Upload firewall logs to automatically analyze IPs and generate **AI-powered forensic briefings**.")

# --- 5. Sidebar Configuration ---
st.sidebar.header("Configuration")
st.sidebar.info("The AI Agent is active. Ensure your API keys are in the .env file.")

# --- 6. Main App Logic ---
uploaded_file = st.file_uploader("Upload Firewall Log (CSV)", type=["csv"])

if uploaded_file is not None:
    st.success("File uploaded successfully!")
    
    if st.button("Start SOC Analysis"):
        with st.spinner("Analyzing logs and querying Threat Intelligence APIs..."):
            
            # Save uploaded file temporarily
            with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
                tmp.write(uploaded_file.getvalue())
                tmp_path = tmp.name

            # Extract IPs
            try:
                ips_to_check = extract_unique_ips(tmp_path)
            except Exception as e:
                st.error(f"Error parsing logs: {e}")
                ips_to_check = []
            finally:
                os.remove(tmp_path) 

            if not ips_to_check:
                st.warning("No valid public IPs found in the uploaded log.")
            else:
                st.info(f"Extracted {len(ips_to_check)} unique public IPs. Initiating TI checks...")
                
                checker = ReputationChecker()
                current_results = []
                
                progress_bar = st.progress(0)
                total_ips = len(ips_to_check)
                
                for i, ip in enumerate(ips_to_check):
                    abuse_data = checker.check_abuseipdb(ip)
                    vt_data = checker.check_virustotal(ip)
                    
                    analysis = calculate_risk(abuse_data, vt_data)
                    
                    current_results.append({
                        "IP Address": ip,
                        "AbuseIPDB Score": analysis['abuse_score'],
                        "VirusTotal Engines": analysis['vt_malicious'],
                        "Risk Score": analysis['risk_score'],
                        "Verdict": analysis['verdict']
                    })
                    
                    progress_bar.progress((i + 1) / total_ips)
                    time.sleep(0.5)

                # Store findings in Session State memory
                st.session_state['analysis_results'] = current_results
                st.success("Analysis Complete!")

# --- 7. Display Results (From Memory) ---
if st.session_state['analysis_results'] is not None:
    df = pd.DataFrame(st.session_state['analysis_results'])
    
    st.subheader("📊 Analysis Results")
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Total IPs Analyzed", len(df))
    col2.metric("Critical/High Threats", len(df[df['Verdict'].isin(['Critical', 'High'])]))
    col3.metric("Clean IPs", len(df[df['Verdict'] == 'Low']))

    def color_verdict(val):
        if val in ['Critical', 'High']:
            color = '#ff4b4b' 
        elif val == 'Medium':
            color = '#ffa500' 
        else:
            color = '#00cc66' 
        return f'color: {color}; font-weight: bold'

    styled_df = df.style.map(color_verdict, subset=['Verdict'])
    st.dataframe(styled_df, use_container_width=True)

    st.subheader("📈 Threat Distribution")
    verdict_counts = df['Verdict'].value_counts()
    st.bar_chart(verdict_counts)

    # --- 8. AI Agent Forensic Review Section ---
    st.divider()
    st.subheader("🤖 AI Agent Forensic Review")
    st.write("The AI Analyst will review the detected threats and suggest a defense strategy.")
    
    if st.button("Generate AI Security Briefing"):
        with st.spinner("AI Agent is investigating the dataset..."):
            # Prepare data summary for AI
            summary_text = df[['IP Address', 'Risk Score', 'Verdict']].to_string(index=False)
            
            try:
                # Call the AI function
                ai_briefing = analyze_security_event(summary_text)
                st.info(ai_briefing)
            except Exception as e:
                st.error(f"AI Agent Error: {e}")
                st.warning("Please check if your OpenAI API Key is valid and has credits.")