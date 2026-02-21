"""Module for risk scoring and verdict generation."""
from typing import Dict, Any

def calculate_risk(abuse_data: Dict[str, Any], vt_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculates a unified risk score based on TI data.
    
    Rules:
    - AbuseIPDB confidence > 75 -> +50
    - VirusTotal malicious > 5 engines -> +40
    - If both thresholds met -> +20 bonus
    - Max score capped at 100.
    
    Args:
        abuse_data (Dict): Data returned from AbuseIPDB.
        vt_data (Dict): Data returned from VirusTotal.
        
    Returns:
        Dict: Contains 'risk_score' and 'verdict'.
    """
    score = 0
    abuse_score = abuse_data.get('score', 0)
    vt_malicious = vt_data.get('malicious_count', 0)
    
    hit_abuse = False
    hit_vt = False
    
    # Rule 1
    if abuse_score > 75:
        score += 50
        hit_abuse = True
        
    # Rule 2
    if vt_malicious > 5:
        score += 40
        hit_vt = True
        
    # Rule 3 (Bonus correlation)
    if hit_abuse and hit_vt:
        score += 20
        
    # Scale proportional scores for items under threshold
    if not hit_abuse and abuse_score > 0:
        score += int((abuse_score / 75) * 20)  # Max +20 for under-threshold
    if not hit_vt and vt_malicious > 0:
        score += int((vt_malicious / 5) * 20)  # Max +20 for under-threshold
        
    # Cap at 100
    final_score = min(score, 100)
    
    # Determine Verdict
    if final_score >= 80:
        verdict = "Critical"
    elif final_score >= 50:
        verdict = "High"
    elif final_score >= 20:
        verdict = "Medium"
    else:
        verdict = "Low"
        
    return {
        "risk_score": final_score,
        "verdict": verdict,
        "abuse_score": abuse_score,
        "vt_malicious": vt_malicious
    }