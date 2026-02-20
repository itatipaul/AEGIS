import sys
import os
import argparse
import time
import json
import shutil

# --- BOOTSTRAP PATH FIX ---
current_file_path = os.path.abspath(__file__)
current_dir = os.path.dirname(current_file_path)
parent_dir = os.path.dirname(current_dir)

if current_dir in sys.path:
    sys.path.remove(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
# --------------------------

try:
    from aegis.core.engine import AegisEngine
    from aegis.core.knowledge import KnowledgeBase
    from aegis.core.utils import load_config, setup_logging
    from aegis.core.display import display
    from aegis.core.traffic_control import TrafficController
    from aegis.core.database import db 
except ImportError as e:
    print(f"\n[!] CRITICAL STARTUP ERROR: {e}")
    sys.exit(1)

def main():
    display.print_banner()
    
    parser = argparse.ArgumentParser(description="AEGIS: Tier-6 Red Team Framework")
    parser.add_argument("-t", "--target", help="Target Domain or IP")
    
    # NEW: Mode Selector
    parser.add_argument("-m", "--mode", 
        choices=["network", "port", "script", "full", "udp", "vulns", "recon", "all"],
        default="all",
        help="Select Scanning Mode"
    )
    
    parser.add_argument("--stealth", action="store_true", help="Enable random delays and UA rotation")
    parser.add_argument("--proxy", help="HTTP Proxy")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()

    # 1. Target Validation
    target = args.target
    if not target:
        display.log("Target is required. Use -t <target>", "ERROR")
        return

    # 2. Init
    logger = setup_logging("aegis.log", verbose=args.verbose)
    global_settings = load_config()

    # 3. KnowledgeBase
    kb = KnowledgeBase(load_existing=False) 
    kb.reset() 
    kb.update("target_domain", target)

    # 4. Mode Configuration
    display.log(f"Engaging Mode: [bold cyan]{args.mode.upper()}[/bold cyan]", "INFO")
    
    runtime_config = {
        "stealth": args.stealth,
        "mode": args.mode,  # Pass mode to plugins
        "proxy": args.proxy,
        "settings": global_settings
    }
    kb.update("config", runtime_config)
    
    if args.stealth or args.proxy:
        tc = TrafficController(runtime_config)
        tc.activate()

    # 5. Load & Filter Engine
    engine = AegisEngine(kb)
    engine.load_plugins(mode=args.mode) # Filter plugins by mode

    # 6. Execute
    try:
        engine.start()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
    finally:
        display.print_mission_report(kb)
        
        # Auto-Export JSON
        try:
            report_data = kb.get_all()
            filename = f"report_{target}_{args.mode}.json"
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=4, default=str)
            display.log(f"Report saved to: {filename}", "SUCCESS")
        except: pass

if __name__ == "__main__":
    main()
