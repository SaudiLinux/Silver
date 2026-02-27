"""
Security Reporter Module for Dr-Sayer
Author: SayerLinux (SayerLinux@outlook.sa)
"""

import json
import time
import os
import hashlib
from datetime import datetime
from typing import List, Dict, Any
from html import escape

class SecurityReporter:
    """Generate comprehensive security testing reports"""
    
    def __init__(self):
        self.report_templates = {
            'html': self.generate_html_report,
            'json': self.generate_json_report,
            'txt': self.generate_text_report
        }
        
        # Severity colors for HTML reports
        self.severity_colors = {
            'Critical': '#dc3545',
            'High': '#fd7e14',
            'Medium': '#ffc107',
            'Low': '#28a745',
            'Info': '#17a2b8'
        }
        
        # Severity weights for sorting
        self.severity_weights = {
            'Critical': 5,
            'High': 4,
            'Medium': 3,
            'Low': 2,
            'Info': 1
        }
    
    def generate_report(self, findings: List[Dict[str, Any]], start_time: datetime, 
                       output_format: str = 'html', output_file: str = None, attack_meta: Dict[str, Any] = None) -> str:
        """Generate security testing report"""
        
        if output_format not in self.report_templates:
            raise ValueError(f"Unsupported format: {output_format}")
        
        # Generate report content
        report_content = self.report_templates[output_format](findings, start_time, attack_meta or {})
        
        # Generate filename if not provided
        if not output_file:
            timestamp = start_time.strftime('%Y%m%d_%H%M%S')
            output_file = f"dr-sayer_report_{timestamp}.{output_format}"
        
        # Ensure reports directory exists
        reports_dir = os.path.join(os.path.dirname(__file__), '..', 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        
        # Full path
        full_path = os.path.join(reports_dir, output_file)
        
        # Write report
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        return full_path
    
    def generate_html_report(self, findings: List[Dict[str, Any]], start_time: datetime, attack_meta: Dict[str, Any] = None) -> str:
        """Generate HTML report"""
        
        # Sort findings by severity
        sorted_findings = sorted(findings, 
                               key=lambda x: self.severity_weights.get(x.get('severity', 'Info'), 0), 
                               reverse=True)
        
        # Calculate statistics
        total_findings = len(findings)
        severity_counts = self.calculate_severity_counts(findings)
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dr-Sayer Security Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            margin-bottom: 40px;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 10px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}
        .header p {{
            margin: 10px 0 0 0;
            font-size: 1.1em;
            opacity: 0.9;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            color: #333;
            font-size: 1.2em;
        }}
        .summary-card .value {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }}
        .severity-chart {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 40px;
        }}
        .severity-bar {{
            flex: 1;
            margin: 0 5px;
            text-align: center;
        }}
        .severity-bar-fill {{
            height: 30px;
            border-radius: 15px;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }}
        .findings-section {{
            margin-top: 40px;
        }}
        .finding {{
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .finding-header {{
            padding: 15px 20px;
            border-bottom: 1px solid #e0e0e0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .severity-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
        }}
        .finding-body {{
            padding: 20px;
        }}
        .finding-details {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-top: 15px;
        }}
        .detail-group {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
        }}
        .detail-group h4 {{
            margin: 0 0 10px 0;
            color: #495057;
            font-size: 1em;
        }}
        .code-block {{
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 5px;
            padding: 10px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        .evidence {{
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 5px;
            padding: 10px;
            margin-top: 10px;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
            color: #6c757d;
        }}
        .module-section {{
            margin-bottom: 30px;
        }}
        .module-title {{
            background: #667eea;
            color: white;
            padding: 10px 15px;
            border-radius: 5px;
            margin-bottom: 15px;
            font-weight: bold;
        }}
        @media (max-width: 768px) {{
            .finding-details {{
                grid-template-columns: 1fr;
            }}
            .severity-chart {{
                flex-direction: column;
            }}
            .severity-bar {{
                margin: 5px 0;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Dr-Sayer Security Report</h1>
            <p>Comprehensive Security Testing Report</p>
            <p><strong>Generated:</strong> {start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="value">{total_findings}</div>
            </div>
            <div class="summary-card">
                <h3>Critical</h3>
                <div class="value" style="color: {self.severity_colors['Critical']};">{severity_counts['Critical']}</div>
            </div>
            <div class="summary-card">
                <h3>High</h3>
                <div class="value" style="color: {self.severity_colors['High']};">{severity_counts['High']}</div>
            </div>
            <div class="summary-card">
                <h3>Medium</h3>
                <div class="value" style="color: {self.severity_colors['Medium']};">{severity_counts['Medium']}</div>
            </div>
        </div>
        
        <div class="severity-chart">
            {self.generate_severity_chart_html(severity_counts)}
        </div>
        
        {"<div class=\"module-section\"><div class=\"module-title\">سطح الاستغلال والهجوم</div><div class=\"finding\"><div class=\"finding-body\"><p>" + escape(str(attack_meta.get('attack_surface_ar',''))).replace("\\n","<br>") + "</p></div></div></div>" if attack_meta and attack_meta.get('attack_surface_ar') else ""}
        {"<div class=\"module-section\"><div class=\"module-title\">متجه الهجوم</div><div class=\"finding\"><div class=\"finding-body\"><p>" + escape(str(attack_meta.get('attack_vector_ar',''))).replace("\\n","<br>") + "</p></div></div></div>" if attack_meta and attack_meta.get('attack_vector_ar') else ""}
        
        <div class="findings-section">
            <h2>🚨 Security Findings</h2>
            {self.generate_findings_html(sorted_findings)}
        </div>
        
        <div class="footer">
            <p><strong>Dr-Sayer Security Tool</strong></p>
            <p>Author: SayerLinux | Email: SayerLinux@outlook.sa</p>
            <p>⚠️ This report is for authorized security testing only</p>
        </div>
    </div>
</body>
</html>
        """
        
        return html_content.strip()
    
    def generate_severity_chart_html(self, severity_counts: Dict[str, int]) -> str:
        """Generate severity chart HTML"""
        max_count = max(severity_counts.values()) if severity_counts else 1
        
        chart_html = ""
        for severity, count in severity_counts.items():
            percentage = (count / max_count * 100) if max_count > 0 else 0
            color = self.severity_colors.get(severity, '#6c757d')
            
            chart_html += f"""
            <div class="severity-bar">
                <div class="severity-bar-fill" style="background-color: {color}; width: {percentage}%;">
                    {count}
                </div>
                <div><strong>{severity}</strong></div>
            </div>
            """
        
        return chart_html
    
    def generate_findings_html(self, findings: List[Dict[str, Any]]) -> str:
        """Generate findings section HTML"""
        if not findings:
            return "<div class='finding'><div class='finding-body'><p>No vulnerabilities found.</p></div></div>"
        
        findings_html = ""
        
        # Group findings by module
        module_groups = {}
        for finding in findings:
            module = finding.get('module', 'Unknown Module')
            if module not in module_groups:
                module_groups[module] = []
            module_groups[module].append(finding)
        
        for module, module_findings in module_groups.items():
            findings_html += f"<div class='module-section'>"
            findings_html += f"<div class='module-title'>{escape(str(module))}</div>"
            
            for finding in module_findings:
                findings_html += self.generate_single_finding_html(finding)
            
            findings_html += "</div>"
        
        return findings_html
    
    def generate_single_finding_html(self, finding: Dict[str, Any]) -> str:
        """Generate single finding HTML"""
        severity = finding.get('severity', 'Info')
        color = self.severity_colors.get(severity, '#6c757d')
        
        finding_html = f"""
        <div class="finding">
            <div class="finding-header">
                <div>
                    <strong>{escape(str(finding.get('type', 'Unknown')))}</strong>
                    {f" - {escape(str(finding.get('location', '')))}" if finding.get('location') else ""}
                </div>
                <span class="severity-badge" style="background-color: {color};">{severity}</span>
            </div>
            <div class="finding-body">
                <p>{escape(str(finding.get('description', 'No description provided')))}</p>
                
                <div class="finding-details">
                    <div class="detail-group">
                        <h4>Payload</h4>
                        <div class="code-block">{escape(str(finding.get('payload', 'N/A')))}</div>
                    </div>
                    <div class="detail-group">
                        <h4>Evidence</h4>
                        <div class="code-block">{escape(str(finding.get('evidence', 'N/A')))[:200]}...</div>
                    </div>
                </div>
                
                {f"<div class='evidence'><strong>Additional Evidence:</strong><br>{escape(str(finding.get('additional_evidence', '')))}</div>" if finding.get('additional_evidence') else ""}
                
                <div style="margin-top: 15px; font-size: 0.9em; color: #6c757d;">
                    {f"<strong>URL:</strong> {escape(str(finding.get('url', 'N/A')))}<br>" if finding.get('url') else ""}
                    {f"<strong>Method:</strong> {escape(str(finding.get('method', 'N/A')))}<br>" if finding.get('method') else ""}
                    {f"<strong>Parameter:</strong> {escape(str(finding.get('parameter', 'N/A')))}<br>" if finding.get('parameter') else ""}
                    {f"<strong>Database:</strong> {escape(str(finding.get('database', 'N/A')))}<br>" if finding.get('database') else ""}
                    {f"<strong>CVE Reference:</strong> {escape(str(finding.get('cve_reference', 'N/A')))}<br>" if finding.get('cve_reference') else ""}
                </div>
            </div>
        </div>
        """
        
        return finding_html
    
    def generate_json_report(self, findings: List[Dict[str, Any]], start_time: datetime, attack_meta: Dict[str, Any] = None) -> str:
        """Generate JSON report"""
        
        report_data = {
            'report_metadata': {
                'tool': 'Dr-Sayer Security Tool',
                'version': '1.0.0',
                'author': 'SayerLinux',
                'email': 'SayerLinux@outlook.sa',
                'generated_at': start_time.isoformat(),
                'report_id': hashlib.sha256(str(start_time).encode()).hexdigest()[:16]
            },
            'summary': {
                'total_findings': len(findings),
                'severity_breakdown': self.calculate_severity_counts(findings),
                'testing_duration': str(datetime.now() - start_time)
            },
            'findings': findings,
            'statistics': self.generate_statistics(findings),
            'attack_info': {
                'attack_surface_ar': (attack_meta or {}).get('attack_surface_ar'),
                'attack_vector_ar': (attack_meta or {}).get('attack_vector_ar')
            }
        }
        
        return json.dumps(report_data, indent=2, default=str)
    
    def generate_text_report(self, findings: List[Dict[str, Any]], start_time: datetime, attack_meta: Dict[str, Any] = None) -> str:
        """Generate text report"""
        
        severity_counts = self.calculate_severity_counts(findings)
        
        report_lines = [
            "=" * 80,
            "           Dr-Sayer Security Testing Report",
            "=" * 80,
            "",
            f"Generated: {start_time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Tool: Dr-Sayer v1.0.0",
            f"Author: SayerLinux (SayerLinux@outlook.sa)",
            "",
            "⚠️  WARNING: For authorized security testing only!",
            "",
            "=" * 80,
            "                           SUMMARY",
            "=" * 80,
            "",
            f"Total Findings: {len(findings)}",
            "",
            "سطح الاستغلال والهجوم:",
            str((attack_meta or {}).get('attack_surface_ar') or "").strip(),
            "",
            "متجه الهجوم:",
            str((attack_meta or {}).get('attack_vector_ar') or "").strip(),
            "",
            "Severity Breakdown:",
            f"  Critical: {severity_counts['Critical']}",
            f"  High:     {severity_counts['High']}",
            f"  Medium:   {severity_counts['Medium']}",
            f"  Low:      {severity_counts['Low']}",
            f"  Info:     {severity_counts['Info']}",
            "",
            f"Testing Duration: {datetime.now() - start_time}",
            "",
            "=" * 80,
            "                         DETAILED FINDINGS",
            "=" * 80,
            ""
        ]
        
        if not findings:
            report_lines.append("No vulnerabilities found.")
        else:
            # Sort by severity
            sorted_findings = sorted(findings, 
                                   key=lambda x: self.severity_weights.get(x.get('severity', 'Info'), 0), 
                                   reverse=True)
            
            for i, finding in enumerate(sorted_findings, 1):
                report_lines.extend([
                    f"Finding #{i}",
                    "-" * 40,
                    f"Type:        {finding.get('type', 'Unknown')}",
                    f"Severity:    {finding.get('severity', 'Info')}",
                    f"Description: {finding.get('description', 'No description')}",
                    f"Payload:     {finding.get('payload', 'N/A')}",
                ])
                
                if finding.get('location'):
                    report_lines.append(f"Location:    {finding['location']}")
                
                if finding.get('url'):
                    report_lines.append(f"URL:         {finding['url']}")
                
                if finding.get('parameter'):
                    report_lines.append(f"Parameter:   {finding['parameter']}")
                
                if finding.get('evidence'):
                    report_lines.append(f"Evidence:    {str(finding['evidence'])[:100]}...")
                
                if finding.get('cve_reference'):
                    report_lines.append(f"CVE:         {finding['cve_reference']}")
                
                report_lines.append("")
        
        report_lines.extend([
            "=" * 80,
            "                            STATISTICS",
            "=" * 80,
            "",
            self.generate_statistics_text(findings),
            "",
            "=" * 80,
            "                          RECOMMENDATIONS",
            "=" * 80,
            "",
            self.generate_recommendations_text(findings),
            "",
            "=" * 80,
            "                           DISCLAIMER",
            "=" * 80,
            "",
            "This report is generated for authorized security testing purposes only.",
            "The user is responsible for ensuring proper authorization before using",
            "this tool. Misuse may violate applicable laws.",
            "",
            "For support: SayerLinux@outlook.sa",
            "",
            "=" * 80
        ])
        
        return "\\n".join(report_lines)
    
    def calculate_severity_counts(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate severity counts"""
        counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        
        for finding in findings:
            severity = finding.get('severity', 'Info')
            if severity in counts:
                counts[severity] += 1
            else:
                counts['Info'] += 1
        
        return counts
    
    def generate_statistics(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate statistics about findings"""
        if not findings:
            return {'message': 'No findings to analyze'}
        
        # Group by type
        type_counts = {}
        for finding in findings:
            finding_type = finding.get('type', 'Unknown')
            type_counts[finding_type] = type_counts.get(finding_type, 0) + 1
        
        # Most common vulnerability types
        most_common = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Module distribution
        module_counts = {}
        for finding in findings:
            module = finding.get('module', 'Unknown')
            module_counts[module] = module_counts.get(module, 0) + 1
        
        return {
            'total_findings': len(findings),
            'type_distribution': type_counts,
            'most_common_types': most_common,
            'module_distribution': module_counts,
            'severity_breakdown': self.calculate_severity_counts(findings)
        }
    
    def generate_statistics_text(self, findings: List[Dict[str, Any]]) -> str:
        """Generate statistics as text"""
        stats = self.generate_statistics(findings)
        
        if 'message' in stats:
            return stats['message']
        
        lines = [
            f"Total Findings: {stats['total_findings']}",
            "",
            "Most Common Vulnerability Types:",
        ]
        
        for vuln_type, count in stats['most_common_types']:
            lines.append(f"  {vuln_type}: {count}")
        
        lines.extend([
            "",
            "Module Distribution:",
        ])
        
        for module, count in stats['module_distribution'].items():
            lines.append(f"  {module}: {count}")
        
        return "\\n".join(lines)
    
    def generate_recommendations_text(self, findings: List[Dict[str, Any]]) -> str:
        """Generate recommendations based on findings"""
        if not findings:
            return "No findings - security posture appears strong. Continue regular security assessments."
        
        recommendations = []
        severity_counts = self.calculate_severity_counts(findings)
        
        if severity_counts['Critical'] > 0:
            recommendations.append("🚨 CRITICAL: Address critical vulnerabilities immediately")
            recommendations.append("   - Implement emergency patches")
            recommendations.append("   - Consider temporary mitigations")
        
        if severity_counts['High'] > 0:
            recommendations.append("⚠️  HIGH: Prioritize high-severity vulnerabilities")
            recommendations.append("   - Schedule urgent remediation")
            recommendations.append("   - Implement additional monitoring")
        
        if severity_counts['Medium'] > 0:
            recommendations.append("⚡ MEDIUM: Address medium-severity vulnerabilities in next maintenance cycle")
        
        # Type-specific recommendations
        vuln_types = set(finding.get('type', '') for finding in findings)
        
        if 'SQL Injection' in vuln_types:
            recommendations.append("🔒 SQL Injection: Implement parameterized queries and input validation")
        
        if 'Cross-Site Scripting (XSS)' in vuln_types:
            recommendations.append("🛡️  XSS: Implement output encoding and Content Security Policy (CSP)")
        
        if 'Log4j Injection (CVE-2021-44228)' in vuln_types:
            recommendations.append("🪲 Log4j: Update Log4j to patched version and implement input sanitization")
        
        recommendations.extend([
            "",
            "General Recommendations:",
            "• Implement Web Application Firewall (WAF)",
            "• Regular security testing and vulnerability assessments",
            "• Security awareness training for development team",
            "• Implement secure coding practices",
            "• Regular dependency updates and patch management"
        ])
        
        return "\\n".join(recommendations)
