from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich.logging import RichHandler
from rich.text import Text
from rich import box
from datetime import datetime
import logging
import random

class DisplayManager:
    def __init__(self):
        self.console = Console()
        
        # --- LOGGING BRIDGE ---
        logging.basicConfig(
            level="INFO",
            format="%(message)s",
            datefmt="[%X]",
            handlers=[
                RichHandler(
                    console=self.console, 
                    show_time=False, 
                    show_path=False, 
                    markup=True,
                    rich_tracebacks=True
                )
            ],
            force=True
        )
        
    def print_banner(self):
        # BANNER LIBRARY
        banners = [
            # 1. THE CLASSIC (Green)
            """[bold green]
    ___    __________________
   /   |  / ____/ ____/  _/ ___/
  / /| | / __/ / / __ / / \__ \ 
 / ___ |/ /___/ /_/ // / ___/ / 
/_/  |_/_____/\____/___//____/  
[/bold green]""",

            # 2. CYBERPUNK (Cyan/Blue)
            """[bold cyan]
   ▄▄▄       ██▓█████  ▄████  ██▓  ██████ 
  ▒████▄    ▓██▓  ██▒ ██▒ ▀█▒▓██▒▒██    ▒ 
  ▒██  ▀█▄  ▒██▒ ▓██▒▒██░▄▄▄░▒██▒░ ▓██▄   
  ░██▄▄▄▄██ ░██░ ▓██░░▓█  ██▓░██░  ▒   ██▒
   ▓█   ▓██▒░██░ ▒██▒░▒▓███▀▒░██░▒██████▒▒
   ▒▒   ▓▒█░░▓   ▒ ░░ ░▒   ▒ ░▓  ▒ ▒▓▒ ▒ ░
[/bold cyan]""",

            # 3. RED ALERT (Red)
            """[bold red]
      _    _____ ____ ___ ____ 
     / \  | ____/ ___|_ _/ ___|
    / _ \ |  _|| |  _ | |\___ \ 
   / ___ \| |__| |_| || | ___) |
  /_/   \_\_____\____|___|____/ 
[/bold red]""",

            # 4. RETRO BLOCK (Purple)
            """[bold magenta]
 ▄▄▄· ▄▄▄ . ▄▄ • ▪  .▄▄ · 
▐█ ▀█ ▀▄.▀·▐█ ▀ ▪██ ▐█ ▀. 
▄█▀▀█ ▐▀▀▪▄▄█ ▀█▄▐█·▄▀▀▀█▄
▐█ ▪▐▌▐█▄▄▌▐█▄▪▐█▐█▌▐█▄▪▐█
 ▀  ▀  ▀MQ▀ ·▀▀▀▀ ▀▀ ▀▀▀▀ 
[/bold magenta]""",

            # 5. COMPACT (Yellow)
            """[bold yellow]
    (        )  (      (     
    )\    ( /(  )\ )   )\ )  
  (((_)   )\())(()/(  (()/(  
  )\___  ((_)\  /(_))  /(_)) 
 ((/ __|  | __|(_))   (_)    
  | (__   | _| / -_)  | |    
   \___|  |___|\___|  |_|    
[/bold yellow]"""
        ]
        
        # Select Random Banner
        selected = random.choice(banners)
        
        # Metadata
        meta = "[bold white]AEGIS FRAMEWORK v1.0[/bold white]\n[dim]Advanced Enumeration & Global Intelligence System[/dim]"
        
        # Print
        self.console.print(Panel(Align.center(f"{selected}\n{meta}"), style="blue on black", border_style="blue"))

    def log(self, message, level="INFO"):
        """Fancy logging with timestamps and icons"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {"INFO": "blue", "SUCCESS": "green", "WARNING": "yellow", "ERROR": "red", "CRITICAL": "white on red", "DEBUG": "dim white"}
        icon = {"INFO": "[*]", "SUCCESS": "[+]", "WARNING": "[!]", "ERROR": "[-]", "CRITICAL": "[!!!]", "DEBUG": "[D]"}
        c = colors.get(level, "white")
        i = icon.get(level, "[?]")
        self.console.print(f"[grey50]{timestamp}[/grey50] [bold {c}]{i}[/bold {c}] {message}")

    def print_plugin_summary(self, plugin_name, data):
        """Prints individual plugin results as they happen (Real-time)"""
        if not data: return
        headers = list(data[0].keys()) if isinstance(data[0], dict) else ["Data"]
        
        table = Table(
            show_header=True, 
            header_style="bold white on blue", 
            border_style="dim blue", 
            title=f"MODULE: {plugin_name}", 
            expand=True
        )
        
        for h in headers: table.add_column(h)
        
        for item in data:
            row = []
            for key in headers:
                val = str(item.get(key, "-"))
                if any(x in val.lower() for x in ["crit", "high", "admin", "root"]): val = f"[bold red]{val}[/bold red]"
                elif any(x in val.lower() for x in ["open", "200", "success"]): val = f"[green]{val}[/green]"
                row.append(val)
            table.add_row(*row)
            
        self.console.print(table)
        self.console.print("\n")

    # ---------------------------------------------------------------------
    # THE DETAILED MISSION REPORT (This is what was missing)
    # ---------------------------------------------------------------------
    def print_mission_report(self, kb):
        self.console.print("\n")
        self.console.rule("[bold cyan]MISSION COMPLETE: INTELLIGENCE REPORT[/bold cyan]")
        self.console.print("\n")

        target = kb.get("target_domain", "Unknown")
        
        # 1. OVERVIEW
        grid = Table.grid(expand=True)
        grid.add_column()
        grid.add_column(justify="right")
        grid.add_row(
            f"[bold]Target:[/bold] {target}", 
            f"[bold]Scan Date:[/bold] {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        )
        os_info = kb.get('os_info', 'Unknown')
        waf_info = kb.get('waf_status', {}).get('protection_level', 'Unknown')
        grid.add_row(f"[bold]OS:[/bold] {os_info}", f"[bold]WAF:[/bold] {waf_info}")
        
        self.console.print(Panel(grid, style="white on blue", border_style="cyan"))

        # 2. OPEN PORTS
        raw_ports = kb.get("open_ports", [])
        ports = []

        # Universal Normalizer (Handles List vs Dict conflict)
        if isinstance(raw_ports, list):
            ports = raw_ports
        elif isinstance(raw_ports, dict):
            for k, v in raw_ports.items():
                if isinstance(v, list):
                    ports.extend(v)
                elif isinstance(v, dict):
                    if 'port' not in v: v['port'] = k
                    ports.append(v)

        t_ports = Table(title="[bold green]NETWORK PERIMETER[/bold green]", show_header=True, header_style="bold green", expand=True, box=box.SIMPLE)
        t_ports.add_column("PORT", style="cyan", width=8)
        t_ports.add_column("SERVICE", style="white", width=15)
        t_ports.add_column("BANNER / VERSION", style="dim white", overflow="fold")
        
        if not ports:
            t_ports.add_row("-", "No open ports found", "-")
        else:
            # Deduplicate
            seen = set()
            unique_ports = []
            for p in ports:
                if isinstance(p, dict):
                    pid = p.get("port")
                    if pid and pid not in seen:
                        seen.add(pid)
                        unique_ports.append(p)
            
            # Sort
            unique_ports.sort(key=lambda x: int(x.get("port", 0)) if str(x.get("port")).isdigit() else 99999)

            for p in unique_ports:
                t_ports.add_row(
                    str(p.get("port", "-")), 
                    p.get("service", "-"), 
                    str(p.get("banner", "-"))
                )
        self.console.print(t_ports)
        self.console.print("\n")

        # 3. TECHNOLOGIES
        tech = kb.get("tech_stack", [])
        if tech:
            t_tech = Table(title="[bold magenta]TECHNOLOGY STACK[/bold magenta]", show_header=True, header_style="bold magenta", expand=True, box=box.SIMPLE)
            t_tech.add_column("COMPONENT", width=20)
            t_tech.add_column("NAME", style="bold white", width=20)
            t_tech.add_column("VERSION", style="yellow", width=15)
            t_tech.add_column("SOURCE", style="dim cyan")

            for t in tech:
                if isinstance(t, dict):
                    t_tech.add_row(
                        t.get("COMPONENT","-"), 
                        t.get("NAME","-"), 
                        t.get("VERSION", "Unknown"),
                        t.get("SOURCE", "-")
                    )
            self.console.print(t_tech)
            self.console.print("\n")

        # 4. VULNERABILITIES
        vulns = []
        vulns.extend(kb.get("web_vulns", []) or [])
        vulns.extend(kb.get("nuclei_vulns", []) or [])
        vulns.extend(kb.get("wp_vulns", []) or [])
        
        for n in kb.get("nikto_vulns", []) or []:
             vulns.append({"RISK": "INFO", "TYPE": "Config", "ISSUE": n.get("msg", ""), "EVIDENCE": n.get("url", "-")})

        for d in kb.get("google_dorks", []) or []:
             vulns.append({"RISK": "INFO", "TYPE": "Dork", "ISSUE": d.get("query", ""), "EVIDENCE": d.get("link", "-")})

        if vulns:
            def risk_score(v):
                r = (v.get("RISK") or v.get("SEVERITY", "")).upper()
                if "CRIT" in r: return 0
                if "HIGH" in r: return 1
                if "MED" in r: return 2
                return 3
            
            clean_vulns = [v for v in vulns if isinstance(v, dict)]
            clean_vulns.sort(key=risk_score)

            t_vuln = Table(title="[bold red]VULNERABILITIES[/bold red]", show_header=True, header_style="bold white on red", expand=True, box=box.HEAVY_EDGE)
            t_vuln.add_column("RISK", width=10, justify="center")
            t_vuln.add_column("TYPE", width=20)
            t_vuln.add_column("ISSUE / FINDING", overflow="fold")
            t_vuln.add_column("EVIDENCE / PAYLOAD", style="dim", overflow="fold")

            for v in clean_vulns:
                risk = (v.get("RISK") or v.get("SEVERITY", "INFO")).upper()
                vtype = v.get("TYPE") or v.get("CATEGORY", "-")
                issue = v.get("ISSUE") or v.get("TEMPLATE") or v.get("FINDING", "-")
                evidence = v.get("EVIDENCE") or v.get("MATCHED_AT") or ""
                
                r_style = "white"
                if "CRIT" in risk: r_style = "bold white on red"
                elif "HIGH" in risk: r_style = "red"
                elif "MED" in risk: r_style = "yellow"
                
                t_vuln.add_row(f"[{r_style}]{risk}[/{r_style}]", vtype, str(issue), str(evidence))
            
            self.console.print(t_vuln)
            self.console.print("\n")

        # 5. SECRETS
        secrets = kb.get("leaked_secrets", [])
        if secrets:
            t_sec = Table(title="[bold yellow]LEAKED INTELLIGENCE[/bold yellow]", show_header=True, header_style="bold black on yellow", expand=True, box=box.DOUBLE)
            t_sec.add_column("TYPE", width=20)
            t_sec.add_column("LOCATION", width=30, overflow="fold")
            t_sec.add_column("VALUE", overflow="fold") 
            
            for s in secrets:
                if isinstance(s, dict):
                    val = str(s.get("data") or s.get("SECRET", ""))
                    t_sec.add_row(
                        s.get("type", "Secret"),
                        s.get("source", "Unknown"),
                        f"[red]{val}[/red]"
                    )
            self.console.print(t_sec)

        self.console.rule("[bold cyan]END OF REPORT[/bold cyan]")
        self.console.print("\n")

# Global instance
display = DisplayManager()
