# aegis/plugins/report/json_exporter.py
import json
import os
from datetime import datetime

# Runs extremely late, after HTML report
PRIORITY = 101
TYPE = "Reporting"
DESCRIPTION = "Exports full scan data to machine-readable JSON"

def run(kb):
    print("[*] Generating JSON Artifacts...")
    
    # Use the new get_all() method from our upgraded brain
    if hasattr(kb, 'get_all'):
        full_data = kb.get_all()
    else:
        # Fallback for old brain compatibility
        full_data = kb.data

    target = full_data.get("target_domain", "scan_results")
    
    # Clean the target name for a filename
    safe_target = "".join([c for c in target if c.isalpha() or c.isdigit() or c in ('-', '_')]).rstrip()
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"aegis_results_{safe_target}_{timestamp}.json"
    
    # Metadata wrapper
    export_object = {
        "meta": {
            "tool": "AEGIS Framework",
            "version": "4.8.0",
            "scan_time": datetime.now().isoformat(),
            "target": target
        },
        "findings": full_data
    }

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(export_object, f, indent=4, default=str)
            
        print(f"      [+] JSON Export saved: {os.path.abspath(filename)}")
        
    except Exception as e:
        print(f"      [!] Failed to export JSON: {e}")
