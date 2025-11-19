"""
Evaluates how risky/suspicious a binary file appears to be.
"""


def calculate_risk_level(analysis_data):
    """
    Look at all the suspicious stuff we found and give it a risk rating.
    Returns: 'Critical', 'High', 'Medium', or 'Low'
    """
    score = 0
    reasons = []
    
    basic_info = analysis_data.get('basic_info', {})
    
    # Weird compilation timestamp
    timestamp = basic_info.get('compilation_timestamp', 0)
    if timestamp == 0 or timestamp < 946684800:  # Before year 2000
        score += 1
        reasons.append("Suspicious compilation timestamp")
    
    # Check section entropy - really high entropy often means packing
    high_entropy_sections = 0
    for section in analysis_data.get('sections', []):
        if section.get('entropy', 0) > 7.8:
            high_entropy_sections += 1
    
    if high_entropy_sections >= 2:
        score += 4
        reasons.append(f"Multiple high entropy sections ({high_entropy_sections})")
    elif high_entropy_sections == 1:
        score += 1
        reasons.append("Single high entropy section")
    
    # Count really bad API calls vs just suspicious ones
    critical_count = 0
    suspicious_count = 0
    
    critical_apis = [
        'CreateRemoteThread', 'WriteProcessMemory', 'NtCreateThreadEx',
        'VirtualAllocEx', 'NtAllocateVirtualMemory', 'RtlCreateUserThread',
        'SetWindowsHookEx', 'GetAsyncKeyState', 'BlockInput'
    ]
    
    for imp in analysis_data.get('suspicious_imports', []):
        func_name = imp.get('function', '')
        if any(api in func_name for api in critical_apis):
            critical_count += 1
        else:
            suspicious_count += 1
    
    score += critical_count * 3
    score += min(suspicious_count, 5)  # Cap it so we don't over-score
    
    if critical_count > 0:
        reasons.append(f"Critical malware APIs found ({critical_count})")
    if suspicious_count > 0:
        reasons.append(f"Suspicious APIs found ({suspicious_count})")
    
    # Known packer signatures are bad news
    packer_sigs = 0
    packer_patterns = 0
    
    for finding in analysis_data.get('suspicious_findings', []):
        if finding['type'] == 'packer_signature':
            packer_sigs += 1
        elif finding['type'] == 'packer_pattern':
            packer_patterns += 1
    
    if packer_sigs > 0:
        score += 3
        reasons.append(f"Known packer detected ({packer_sigs})")
    elif packer_patterns > 0:
        score += 1
        reasons.append(f"Packer patterns found ({packer_patterns})")
    
    # Extra data tacked onto the end of the file
    if analysis_data.get('overlay'):
        overlay_size = analysis_data['overlay'].get('size', 0)
        if overlay_size > 1024 * 1024:  # Over 1MB is sketchy
            score += 2
            reasons.append(f"Large overlay data ({overlay_size} bytes)")
        else:
            score += 0.5
            reasons.append(f"Small overlay data ({overlay_size} bytes)")
    
    # Suspicious strings
    strings_data = analysis_data.get('strings', {})
    
    crypto_wallets = len(strings_data.get('crypto_wallet', []))
    if crypto_wallets > 0:
        score += crypto_wallets * 2
        reasons.append(f"Cryptocurrency wallets ({crypto_wallets})")
    
    suspicious_strings = min(len(strings_data.get('suspicious', [])), 10)
    urls = min(len(strings_data.get('url', [])), 5)
    ip_addrs = min(len(strings_data.get('ip_address', [])), 3)
    
    score += suspicious_strings * 0.3
    score += urls * 0.5
    score += ip_addrs * 0.7
    
    if suspicious_strings > 5:
        reasons.append(f"Many suspicious strings ({len(strings_data.get('suspicious', []))})")
    if urls > 2:
        reasons.append(f"Multiple URLs ({len(strings_data.get('url', []))})")
    if ip_addrs > 1:
        reasons.append(f"Hard-coded IP addresses ({len(strings_data.get('ip_address', []))})")
    
    # Structural weirdness
    anomaly_count = len(analysis_data.get('anomalies', []))
    if anomaly_count > 3:
        score += 2
        reasons.append(f"Many structural anomalies ({anomaly_count})")
    elif anomaly_count > 0:
        score += 0.5
        reasons.append(f"Structural anomalies ({anomaly_count})")
    
    # Lots of exports usually means it's a legitimate library
    exports = analysis_data.get('exports', {}).get('functions', [])
    if len(exports) > 10:
        score -= 1
        reasons.append(f"Looks like a library ({len(exports)} exports)")
    
    # Save the details for reporting
    analysis_data['risk_factors'] = reasons
    analysis_data['risk_score'] = int(score)
    
    # Convert score to risk level
    if score >= 12:
        return 'Critical'
    elif score >= 7:
        return 'High'
    elif score >= 3:
        return 'Medium'
    else:
        return 'Low'
