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

- ✅ Live host discovery with evasion
- ✅ Full protocol enumeration:
  - NetBIOS / SMB Shares & Users
  - SNMP / LDAP / NFS / RPC
  - DNS / NTP / SMTP / SIP / IPSec
- ✅ Runs both:
  - `nmap` with firewall-evasion flags
  - Specialized Kali tools (`nbtscan`, `ldapsearch`, `showmount`, `rpcinfo`, etc.)
- ✅ Auto-generated HTML report with collapsible sections
- ✅ Attack surface analysis with exploit/tool suggestions (e.g., Metasploit modules)
- 🔐 Report is permanently authored:
  ```
  Maintained by Arman Kumar | GitHub: armank8000
  ```

---

## 📦 Requirements

Most tools are pre-installed on Kali Linux. To install any missing ones:

```bash
sudo apt update
sudo apt install nmap nbtscan smbclient enum4linux snmp ldap-utils rpcbind nfs-common \
net-tools dnsutils dnsenum ike-scan smtp-user-enum theharvester sublist3r \
dnsrecon traceroute whois curl
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

**With Custom Output:**

```bash
python3 footprint_advanced.py example.com --output /home/kali/reports/example.html
```

---

### 🧠 Run Full Network Enumerator

```bash
sudo python3 full_evasive_enumerator.py -i 192.168.1.0/24
```

**With HTML Report Output:**

```bash
sudo python3 full_evasive_enumerator.py -i 192.168.1.0/24 -o enum_report.html
```

---

## 📂 Sample Outputs

- `/home/kali/reports/example.html`  
  → Clean domain footprint report

- `enum_report.html`  
  → Interactive collapsible report with:
    * Nmap & Tool Output (side-by-side)
    * Auto attack suggestions with tool mappings

---

## 🤖 Author

**Arman Kumar**  
Cybersecurity | Offensive Security | OSINT | Python Automation  
🔗 [GitHub](https://github.com/armank8000)  
🔗 [LinkedIn](https://linkedin.com/in/arman-kumar8000)

---

## ⭐️ Show Your Support

If this toolkit helped you, please ⭐️ the repo and share it with your team or community!

