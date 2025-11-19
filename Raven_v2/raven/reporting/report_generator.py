"""
Creates analysis reports in different formats (text, JSON, HTML).
"""
import json
import os
from datetime import datetime


def generate_text_report(analysis_results, file_path):
    """Create a human-readable text report."""
    lines = []
    
    lines.append("=" * 80)
    lines.append("RAVEN EXE ANALYSIS REPORT")
    lines.append("=" * 80)
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Target: {os.path.basename(file_path)}")
    lines.append("")
    
    # Basic info
    lines.append("=== BASIC INFORMATION ===")
    for key, value in analysis_results['basic_info'].items():
        lines.append(f"{key.replace('_', ' ').title()}: {value}")
    
    # Hashes
    lines.append("\n=== FILE HASHES ===")
    for algo, hash_val in analysis_results['file_hashes'].items():
        lines.append(f"{algo.upper()}: {hash_val}")
    
    # Risk
    risk = analysis_results['risk']
    lines.append(f"\n=== RISK ASSESSMENT: {risk} ===")
    if 'risk_score' in analysis_results:
        lines.append(f"Risk Score: {analysis_results['risk_score']}")
    if 'risk_factors' in analysis_results and analysis_results['risk_factors']:
        lines.append("Risk Factors:")
        for factor in analysis_results['risk_factors']:
            lines.append(f"  • {factor}")
    
    # Sections
    lines.append("\n=== SECTIONS ===")
    for section in analysis_results['sections']:
        anomaly_text = f" [Anomalies: {', '.join(section['anomalies'])}]" if section['anomalies'] else ""
        lines.append(
            f"{section['name']}: VA=0x{section['virtual_address']:X}, "
            f"Size=0x{section['virtual_size']:X}, Entropy={section['entropy']:.2f}{anomaly_text}"
        )
    
    # Imports (limited)
    if analysis_results['imports']:
        lines.append("\n=== IMPORTS (summary) ===")
        for dll, functions in list(analysis_results['imports'].items())[:5]:
            lines.append(f"{dll}: {len(functions)} functions")
    
    # Suspicious findings
    if analysis_results['suspicious_findings']:
        lines.append("\n=== SUSPICIOUS FINDINGS ===")
        for finding in analysis_results['suspicious_findings']:
            lines.append(f"  • {finding.get('message', 'Unknown')}")
    
    # Anomalies
    if analysis_results['anomalies']:
        lines.append("\n=== STRUCTURAL ANOMALIES ===")
        for anomaly in analysis_results['anomalies']:
            lines.append(f"  • {anomaly.get('message', 'Unknown')}")
    
    # Overlay
    if analysis_results['overlay']:
        lines.append(f"\n=== OVERLAY DATA ===")
        lines.append(analysis_results['overlay']['message'])
    
    return "\n".join(lines)


def generate_json_report(analysis_results):
    """Create a JSON report with all the data."""
    return json.dumps(analysis_results, indent=2, default=str)


def generate_html_report(analysis_results, file_path):
    """Create an HTML report that looks nice in a browser."""
    risk = analysis_results['risk']
    risk_color = {
        'Critical': '#e74c3c',
        'High': '#e67e22',
        'Medium': '#f39c12',
        'Low': '#27ae60'
    }.get(risk, '#95a5a6')
    
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Raven Analysis - {os.path.basename(file_path)}</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .section {{ background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .risk-badge {{ display: inline-block; padding: 10px 20px; border-radius: 5px; font-weight: bold; color: white; background: {risk_color}; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #34495e; color: white; }}
        .suspicious {{ color: #e74c3c; }}
        .warning {{ color: #e67e22; }}
        .code {{ font-family: 'Courier New', monospace; background: #ecf0f1; padding: 2px 5px; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Raven EXE Analysis Report</h1>
        <p>Target: {os.path.basename(file_path)}</p>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="section">
        <h2>Risk Assessment</h2>
        <span class="risk-badge">{risk}</span>
        <p>Risk Score: {analysis_results.get('risk_score', 'N/A')}</p>
    </div>
    
    <div class="section">
        <h2>Basic Information</h2>
        <table>
"""
    
    for key, value in analysis_results['basic_info'].items():
        html += f"<tr><th>{key.replace('_', ' ').title()}</th><td>{value}</td></tr>\n"
    
    html += """
        </table>
    </div>
    
    <div class="section">
        <h2>File Hashes</h2>
        <table>
"""
    
    for algo, hash_val in analysis_results['file_hashes'].items():
        html += f"<tr><th>{algo.upper()}</th><td class='code'>{hash_val}</td></tr>\n"
    
    html += """
        </table>
    </div>
    
    <div class="section">
        <h2>Sections</h2>
        <table>
            <tr><th>Name</th><th>Virtual Addr</th><th>Size</th><th>Entropy</th><th>Flags</th></tr>
"""
    
    for section in analysis_results['sections']:
        entropy_class = 'suspicious' if section['entropy'] > 7.5 else 'warning' if section['entropy'] > 6.5 else ''
        html += f"""
            <tr>
                <td>{section['name']}</td>
                <td>0x{section['virtual_address']:X}</td>
                <td>0x{section['virtual_size']:X}</td>
                <td class='{entropy_class}'>{section['entropy']:.2f}</td>
                <td>{section['characteristics_human']}</td>
            </tr>
"""
    
    html += """
        </table>
    </div>
    
    <div class="section">
        <h2>Suspicious Findings</h2>
        <ul>
"""
    
    if analysis_results['suspicious_findings']:
        for finding in analysis_results['suspicious_findings']:
            html += f"<li class='suspicious'>{finding.get('message', 'Unknown')}</li>\n"
    else:
        html += "<li>No suspicious findings</li>"
    
    html += """
        </ul>
    </div>
</body>
</html>
"""
    
    return html


def save_report(analysis_results, file_path, output_path, format_type='text'):
    """Save a report to a file."""
    try:
        if format_type == 'json':
            content = generate_json_report(analysis_results)
        elif format_type == 'html':
            content = generate_html_report(analysis_results, file_path)
        else:
            content = generate_text_report(analysis_results, file_path)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return True
    except Exception as e:
        print(f"Error saving report: {e}")
        return False
