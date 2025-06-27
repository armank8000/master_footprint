# 🧠 Cyber Recon & Enumeration Toolkit (Kali Linux)

A powerful dual-toolkit designed for advanced network reconnaissance, domain footprinting, and firewall-evasive enumeration. Built with Python and Kali-native tools, it's ideal for red teamers, penetration testers, and OSINT analysts.

---

## 🔧 Tools Included

### 🔍 1. `footprint_advanced.py` – Domain Footprinting Tool

- ✅ DNS Lookup
- ✅ WHOIS Lookup (Python fallback supported)
- ✅ Traceroute & GeoIP via ipinfo.io
- ✅ theHarvester (Email enumeration via Baidu)
- ✅ Social scraping (LinkedIn/Facebook)
- ✅ Subdomain Enumeration via `Sublist3r`
- ✅ `dnsrecon` integration
- ✅ Auto HTML report with styled layout

---

### 🧠 2. `full_evasive_enumerator.py` – Network Enumerator

- ✅ Live host discovery with firewall evasion
- ✅ Full protocol enumeration:
  - NetBIOS / SMB Shares & Users
  - SNMP / LDAP / NFS / RPC
  - DNS / NTP / SMTP
  - 📞 **VoIP SIP (UDP 5060)**
  - IPSec/IKE (VPN detection)
- ✅ Dual-engine scanning:
  - `nmap` with evasive flags
  - Specialized Kali tools (`nbtscan`, `ldapsearch`, `showmount`, `rpcinfo`, `svmap`, etc.)
- ✅ HTML report with collapsible protocol sections
- ✅ Automated attack surface analysis with exploit/tool suggestions
- 🔐 Authorship credit hardcoded:
  ```
  Maintained by Arman Kumar | GitHub: armank8000
  ```

---

## 📦 Requirements

Ensure these packages are installed (most are pre-installed in Kali):

```bash
sudo apt update
sudo apt install nmap nbtscan smbclient enum4linux snmp ldap-utils rpcbind nfs-common \
net-tools dnsutils dnsenum ike-scan smtp-user-enum theharvester sublist3r \
dnsrecon traceroute whois curl svmap
pip install python-whois
```

---

## 🚀 Usage

### Clone the Repo

```bash
git clone https://github.com/armank8000/master_footprint.git
cd master_footprint
```

---

### 🔍 Run Domain Footprinting Tool

```bash
python3 footprint_advanced.py example.com
```

**With Custom HTML Output:**

```bash
python3 footprint_advanced.py example.com --output /home/kali/reports/example.html
```

---

### 🧠 Run Network Enumerator

```bash
sudo python3 full_evasive_enumerator.py -i 192.168.1.0/24
```

**With Collapsible HTML Report:**

```bash
sudo python3 full_evasive_enumerator.py -i 192.168.1.0/24 -o enum_report.html
```

---

## 📂 Output Overview

- `/home/kali/reports/example.html` → Domain recon report
- `enum_report.html` → Collapsible report with:
  - Nmap results
  - Tool-based results
  - Attack surface insights
  - SIP service detection
  - Embedded author attribution

---

## 🤖 Author

**Arman Kumar**  
Cybersecurity | Offensive Security | OSINT | Python Automation  
🔗 [GitHub](https://github.com/armank8000)  
🔗 [LinkedIn](https://linkedin.com/in/arman-kumar8000)

---

## ⭐️ Show Your Support

If this toolkit helped you, please ⭐️ the repo and share it with your team or community!
