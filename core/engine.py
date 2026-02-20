import os
import importlib
import logging
import asyncio
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
try:
    from aegis.core.display import display
except ImportError:
    pass

# Plugin Category Mapping (For User Modes)
MODE_MAPPING = {
    "network": ["network_sweeper", "arp_discover", "nmap_integrator"],
    "port": ["port_scan", "nmap_integrator"],
    "script": ["nmap_integrator"],
    "full": ["ALL"],
    "udp": ["nmap_integrator"],
    "vulns": ["nuclei_integrator", "nmap_integrator", "bypass_403", "git_scanner", "cve_check"],
    "recon": ["subdomain_enum", "shodan_passive", "google_dorks", "tech_detect", "wayback_urls"],
    "all": ["ALL"]
}

# Smart Blocklists (For Target Context)
# If Context is INTERNAL, block these types:
BLOCKLIST_INTERNAL = ["Cloud Recon", "OSINT", "DNS", "Email Security", "WAF", "Google Dorks"]
# If Has Web is FALSE, block these types:
BLOCKLIST_NO_WEB = ["Web Enumeration", "Web Analysis", "Crawling", "XSS", "SQLi", "CMS Analysis", "Vulnerability Scan", "Active Exploitation"]

class AegisEngine:
    def __init__(self, knowledge_base):
        self.kb = knowledge_base
        self.plugins = []
        self.logger = logging.getLogger("aegis.engine")

    def load_plugins(self, mode="all"):
        base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        plugins_dir = os.path.join(base_path, 'plugins')
        
        allowed_plugins = MODE_MAPPING.get(mode, ["ALL"])
        
        found_files = []
        for root, dirs, files in os.walk(plugins_dir):
            for file in files:
                if file.endswith(".py") and not file.startswith("__"):
                    found_files.append(os.path.join(root, file))

        display.log(f"Initializing Engine ({len(found_files)} modules detected)...", "INFO")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold green]Loading modules...[/bold green]"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=display.console
        ) as load_progress:
            
            load_task = load_progress.add_task("Importing", total=len(found_files))
            
            for full_path in found_files:
                rel_path = os.path.relpath(full_path, os.path.dirname(base_path))
                module_name = os.path.basename(full_path)[:-3]
                load_progress.update(load_task, description=f"Loading: {module_name}")
                
                # Mode Filter
                if "ALL" not in allowed_plugins:
                    if "nmap_integrator" in allowed_plugins and module_name == "nmap_integrator":
                        pass
                    elif module_name not in allowed_plugins:
                        load_progress.advance(load_task)
                        continue

                try:
                    import_path = rel_path.replace(os.sep, ".")[:-3]
                    module = importlib.import_module(import_path)
                    if hasattr(module, 'run') and hasattr(module, 'PRIORITY'):
                        self.plugins.append((module.PRIORITY, module))
                except Exception: pass
                
                load_progress.advance(load_task)
        
        self.plugins.sort(key=lambda x: x[0])
        display.log(f"Engine Ready. Loaded {len(self.plugins)} plugins for mode '{mode}'.", "SUCCESS")

    def start(self):
        if not self.plugins: 
            display.log("No plugins loaded.", "WARNING")
            return

        from itertools import groupby
        plugin_groups = []
        for priority, group in groupby(self.plugins, key=lambda x: x[0]):
            plugin_groups.append(list(group))

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=display.console
        ) as progress:
            
            main_task = progress.add_task("[cyan]Overall Progress", total=len(self.plugins))

            for group in plugin_groups:
                tasks = []
                for _, plugin in group:
                    task_id = progress.add_task(f"Running {plugin.__name__.split('.')[-1]}", total=1)
                    tasks.append(self.run_plugin_safe(plugin, loop, progress, task_id, main_task))
                
                # Wait for this priority group to finish
                loop.run_until_complete(asyncio.gather(*tasks))

        loop.close()

    async def run_plugin_safe(self, plugin, loop, progress, task_id, main_task):
        plugin_name = plugin.__name__.split('.')[-1]
        plugin_type = getattr(plugin, "TYPE", "Unknown")
        
        # --- SMART FILTERING LOGIC ---
        profile = self.kb.get("target_profile", {})
        context = profile.get("context", "unknown")
        has_web = profile.get("has_web", True) # Default to True if unknown

        skip = False
        reason = ""

        # 1. Block Internal vs External
        if context == "INTERNAL":
            # Check partial match for Blocklist types
            if any(b in plugin_type for b in BLOCKLIST_INTERNAL):
                skip = True
                reason = "Not relevant for Internal Target"
        
        # 2. Block Web vs Non-Web
        if not has_web and not skip:
             if any(b in plugin_type for b in BLOCKLIST_NO_WEB):
                skip = True
                reason = "No Web Ports (80/443) detected"

        if skip:
            # display.log(f"Skipping {plugin_name}: {reason}", "DEBUG")
            progress.update(task_id, completed=1, visible=False)
            progress.advance(main_task)
            return
        # -----------------------------

        try:
            if hasattr(plugin, 'run_async'):
                await plugin.run_async(self.kb)
            else:
                await loop.run_in_executor(None, plugin.run, self.kb)
        except Exception as e:
            # display.log(f"Plugin {plugin_name} crashed: {e}", "DEBUG")
            pass
        finally:
            progress.update(task_id, completed=1, visible=False)
            progress.advance(main_task)
