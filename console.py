def run_module(self):
        if not self.target and not self.options.get("TARGET"):
            self.console.print("[bold red][!] TARGET not set.[/bold red]")
            return

        # 1. Activate Stealth/Proxy settings
        self.activate_traffic_control()
        
        # 2. Execution logic
        self.engine.load_plugins()
        
        if self.current_module:
            # Execute specific recon module
            target_plugin = next((p for p in self.engine.plugins if self.current_module in p[1].__name__), None)
            
            if target_plugin:
                original = self.engine.plugins
                self.engine.plugins = [target_plugin]
                self.engine.start()
                self.engine.plugins = original
            else:
                self.console.print(f"[bold red][!] Module {self.current_module} not found or is restricted.[/bold red]")
        else:
            # Execute full Technical Discovery Chain
            self.console.print(f"[*] Launching [bold green]TECHNICAL DISCOVERY CHAIN[/bold green] against {self.target}...")
            self.engine.start()
