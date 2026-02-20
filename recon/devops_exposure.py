import requests

PRIORITY = 23
TYPE = "Infrastructure Recon"
DESCRIPTION = "Scans for exposed CI/CD, Docker, and IDE configuration files"

DEVOPS_PATHS = [
    # Containerization
    "docker-compose.yml",
    "docker-compose.yaml",
    "Dockerfile",
    "k8s.yaml",
    "kube/config",
    
    # CI/CD Pipelines
    ".github/workflows/main.yml",
    ".github/workflows/deploy.yml",
    ".gitlab-ci.yml",
    ".circleci/config.yml",
    "Jenkinsfile",
    
    # Package Managers
    "package.json",
    "package-lock.json",
    "composer.json",
    "requirements.txt",
    "Pipfile",
    
    # IDE / Editor Configs (Often contain SFTP creds)
    ".vscode/sftp.json",
    ".idea/workspace.xml",
    ".ds_store"
]

def run(kb):
    target = kb.get("target_domain")
    if not target: return

    print(f"[*] Running DevOps Exposure Scan...")
    
    findings = []
    base_url = f"https://{target}/"

    for path in DEVOPS_PATHS:
        url = base_url + path
        try:
            r = requests.get(url, timeout=4, verify=False)
            
            if r.status_code == 200:
                # Basic False Positive Check: Ensure it's not a generic 200 OK page
                # Config files usually look code-like, not HTML
                if "<html" in r.text.lower() or "<body" in r.text.lower():
                    continue
                    
                print(f"      [!] EXPOSED: {path}")
                findings.append({
                    "id": "DEVOPS-EXPOSURE",
                    "msg": f"Infrastructure Config Exposed: {path}",
                    "url": url,
                    "severity": "HIGH"
                })
        except:
            pass

    if findings:
        kb.update("nikto_vulns", findings)
