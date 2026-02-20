# 🛡️ AEGIS Framework

**Aegis** is a modular, stealthy, and automated Red Team Reconnaissance framework.

> **⚠️ DISCLAIMER**
> This tool is for **educational purposes and authorized security testing only**. The developers are not responsible for any misuse or damage caused by this program. Ensure you have explicit permission before scanning any target.

## 🔥 Key Capabilities

* **Tier 3 Logic Analysis**: Maps authentication flows, API endpoints (GraphQL/REST), and business logic.
* **Active Exploitation**: Auto-exploits SQLi, XSS, SSRF, LFI, and Command Injection.
* **Stealth Mode**: Features a Traffic Controller with jitter, User-Agent rotation, and proxy support.
* **Post-Exploitation**: Automates enumeration on compromised hosts (Linux/Windows) and internal network pivoting.
* **WAF Evasion**: Smart payload mutation engine to bypass filters.

## 🚀 Installation

```bash
git clone https://github.com/itatipaul/AEGIS
cd aegis
pip install -r requirements.txt
python3 ruun.py -t (target)
