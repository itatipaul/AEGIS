import os
import json
import hashlib

PRIORITY = 95
TYPE = "Reporting"
DESCRIPTION = "Generates Interactive Attack Surface & Vulnerability Map"

def run(kb):
    print("[*] Generating Attack Surface & Vulnerability Map...")
    
    if hasattr(kb, 'get_all'):
        data = kb.get_all()
    else:
        data = kb.data

    target = data.get("target_domain", "Target")
    
    nodes = []
    edges = []
    node_ids = set()
    
    def add_node(id, label, group, title=None):
        # Create unique ID to prevent duplicates
        uid = hashlib.md5(id.encode()).hexdigest()
        if uid not in node_ids:
            nodes.append({
                "id": uid, 
                "label": label[:20] + "..." if len(label) > 20 else label, 
                "group": group, 
                "title": title or label
            })
            node_ids.add(uid)
        return uid

    def add_edge(source_id, target_id):
        s_uid = hashlib.md5(source_id.encode()).hexdigest()
        t_uid = hashlib.md5(target_id.encode()).hexdigest()
        if s_uid in node_ids and t_uid in node_ids:
            edges.append({"from": s_uid, "to": t_uid})

    # 1. Root
    root_id = add_node(target, target, "target", "Mission Target")

    # 2. Subdomains (Attack Surface)
    subs = data.get('scope_domains', [])
    if isinstance(subs, set): subs = list(subs)
    
    for s in subs:
        if s == target: continue
        sid = add_node(s, s.replace(f".{target}", ""), "subdomain", s)
        add_edge(target, sid)

    # 3. Critical Vulnerabilities (The "Kill Chain")
    # Consolidating Nikto, SQLi, XSS, SSTI, Firebase findings
    vulns = data.get('nikto_vulns', [])
    
    for v in vulns:
        severity = v.get("severity", "MEDIUM").upper()
        vuln_type = v.get("id", "VULN")
        url = v.get("url", "Unknown")
        
        # We only map High/Critical to keep the graph clean
        if severity in ["HIGH", "CRITICAL"]:
            # Node Label: SQLI, XSS, etc.
            label = vuln_type.split('-')[0] 
            
            # Create a Vulnerability Node
            vid = add_node(f"{vuln_type}_{url}", f"💀 {label}", "vuln", title=f"{v.get('msg')}\n{url}")
            
            # Link it to the specific subdomain/URL if possible, otherwise Root
            # Simple heuristic: see if a subdomain is in the URL
            linked = False
            for s in subs:
                if s in url:
                    s_uid = hashlib.md5(s.encode()).hexdigest()
                    if s_uid in node_ids:
                        add_edge(s, f"{vuln_type}_{url}")
                        linked = True
                        break
            if not linked:
                add_edge(target, f"{vuln_type}_{url}")

    # 4. Technologies
    tech = data.get('tech_stack', {})
    for host, info in tech.items():
        for t in info.get('technologies', []):
            tid = add_node(f"tech_{t}", t, "tech")
            add_edge(host, f"tech_{t}")

    # --- HTML Output ---
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>AEGIS Threat Map: {target}</title>
        <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
        <style>
            body {{ margin: 0; background-color: #0f0f0f; font-family: 'Segoe UI', sans-serif; }}
            #mynetwork {{ width: 100vw; height: 100vh; }}
            .legend {{ position: absolute; top: 20px; left: 20px; background: rgba(30,30,30,0.8); padding: 15px; border-radius: 8px; color: #fff; pointer-events: none; }}
            .dot {{ height: 10px; width: 10px; border-radius: 50%; display: inline-block; margin-right: 10px; }}
        </style>
    </head>
    <body>
        <div class="legend">
            <h3>Threat Topology</h3>
            <div><span class="dot" style="background:#ff4444"></span>Target</div>
            <div><span class="dot" style="background:#ff0000; box-shadow: 0 0 10px #ff0000;"></span>Critical Vulnerability</div>
            <div><span class="dot" style="background:#00bfff"></span>Subdomain</div>
            <div><span class="dot" style="background:#97c2fc"></span>Technology</div>
        </div>
        <div id="mynetwork"></div>
        <script type="text/javascript">
            var nodes = new vis.DataSet({json.dumps(nodes)});
            var edges = new vis.DataSet({json.dumps(edges)});
            var container = document.getElementById('mynetwork');
            var data = {{ nodes: nodes, edges: edges }};
            var options = {{
                nodes: {{ shape: 'dot', font: {{ color: '#e0e0e0' }} }},
                groups: {{
                    target: {{ color: '#ff4444', size: 30, shape: 'diamond' }},
                    vuln: {{ 
                        color: {{ background: '#ff0000', border: '#ff0000' }}, 
                        size: 25, 
                        shape: 'star',
                        shadow: {{ enabled: true, color: '#ff0000', size: 10 }}
                    }},
                    subdomain: {{ color: '#00bfff', size: 15 }},
                    tech: {{ color: '#97c2fc', size: 10, shape: 'square' }}
                }},
                physics: {{ stabilization: false, barnesHut: {{ gravitationalConstant: -3000 }} }}
            }};
            new vis.Network(container, data, options);
        </script>
    </body>
    </html>
    """
    
    with open(f"threat_map_{target.replace('.', '_')}.html", "w") as f:
        f.write(html_content)
    print(f"[+] Threat Map generated: {os.path.abspath(f.name)}")
