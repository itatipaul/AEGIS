import os
import json
from datetime import datetime

PRIORITY = 99 # Run Last
TYPE = "Reporting"
DESCRIPTION = "Generates a Client-Ready HTML Dashboard"

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Aegis Mission Report - {target}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ background-color: #f8f9fa; }}
        .severity-critical {{ background-color: #dc3545; color: white; }}
        .severity-high {{ background-color: #fd7e14; color: white; }}
        .severity-medium {{ background-color: #ffc107; }}
        .severity-low {{ background-color: #0dcaf0; color: white; }}
        .card {{ margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
    </style>
</head>
<body>
<div class="container mt-4">
    <div class="row mb-4">
        <div class="col">
            <h1 class="display-4">🛡️ Aegis Mission Report</h1>
            <p class="lead">Target: <strong>{target}</strong> | Date: {date}</p>
        </div>
        <div class="col-auto">
            <button onclick="window.print()" class="btn btn-primary">Print / PDF</button>
        </div>
    </div>

    <div class="row">
        <div class="col-md-3">
            <div class="card text-center text-white bg-danger mb-3">
                <div class="card-body">
                    <h5 class="card-title">CRITICAL</h5>
                    <p class="card-text display-6">{count_crit}</p>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card text-center text-white bg-warning mb-3">
                <div class="card-body">
                    <h5 class="card-title">HIGH</h5>
                    <p class="card-text display-6">{count_high}</p>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card text-center text-white bg-info mb-3">
                <div class="card-body">
                    <h5 class="card-title">MEDIUM</h5>
                    <p class="card-text display-6">{count_med}</p>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card text-center bg-light mb-3">
                <div class="card-body">
                    <h5 class="card-title">TOTAL ISSUES</h5>
                    <p class="card-text display-6">{total_vulns}</p>
                </div>
            </div>
        </div>
    </div>

    <div class="row">
        <div class="col-md-6">
            <div class="card">
                <div class="card-header bg-dark text-white">Network Perimeter</div>
                <div class="card-body">
                    <table class="table table-sm table-striped">
                        <thead><tr><th>Port</th><th>Service</th><th>Banner</th></tr></thead>
                        <tbody>
                            {port_rows}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="col-md-12">
            <div class="card">
                <div class="card-header bg-dark text-white">Vulnerability Findings</div>
                <div class="card-body">
                    <table class="table table-hover">
                        <thead><tr><th>Sev</th><th>Type</th><th>Issue</th><th>Evidence</th></tr></thead>
                        <tbody>
                            {vuln_rows}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>
</body>
</html>
"""

def run(kb):
    target = kb.get("target_domain", "Unknown")
    print(f"[*] Generating HTML Report for {target}...")
    
    # Gather Data
    ports = kb.get("open_ports", {}).get(target, [])
    # Normalize ports
    port_list = []
    if isinstance(ports, list): port_list = ports
    elif isinstance(ports, dict): 
        # Flatten dict structure if needed
        pass # Assuming list for simplicity from previous fix

    vulns = []
    vulns.extend(kb.get("nuclei_vulns", []) or [])
    vulns.extend(kb.get("web_vulns", []) or [])
    vulns.extend(kb.get("nikto_vulns", []) or [])

    # HTML Fragment Gen
    port_rows = ""
    for p in port_list:
        if isinstance(p, dict):
            port_rows += f"<tr><td>{p.get('port')}</td><td>{p.get('service','-')}</td><td>{p.get('banner','-')}</td></tr>"

    vuln_rows = ""
    stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    
    for v in vulns:
        risk = (v.get("RISK") or v.get("severity") or "INFO").upper()
        if risk in stats: stats[risk] += 1
        
        badge_class = "bg-secondary"
        if "CRIT" in risk: badge_class = "severity-critical"
        elif "HIGH" in risk: badge_class = "severity-high"
        elif "MED" in risk: badge_class = "severity-medium"
        elif "LOW" in risk: badge_class = "severity-low"

        issue = v.get("ISSUE") or v.get("msg") or v.get("id") or "Unknown"
        evidence = v.get("EVIDENCE") or v.get("url") or v.get("matched_at") or "-"
        
        vuln_rows += f"<tr><td><span class='badge {badge_class}'>{risk}</span></td><td>{v.get('TYPE','-')}</td><td>{issue}</td><td><code>{evidence}</code></td></tr>"

    # Assemble
    html = HTML_TEMPLATE.format(
        target=target,
        date=datetime.now().strftime("%Y-%m-%d %H:%M"),
        count_crit=stats["CRITICAL"],
        count_high=stats["HIGH"],
        count_med=stats["MEDIUM"],
        total_vulns=len(vulns),
        port_rows=port_rows,
        vuln_rows=vuln_rows
    )

    filename = f"report_{target}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
        
    print(f"    [+] HTML Dashboard generated: [bold]{filename}[/bold]")
