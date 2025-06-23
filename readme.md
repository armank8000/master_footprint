### 📄 `README.md`

````markdown
# 🕵️‍♂️ Advanced Domain Footprinting Tool (Kali Linux)

A powerful, all-in-one Python script for domain footprinting and reconnaissance — perfect for cybersecurity researchers, penetration testers, and OSINT analysts.

---

## 🔧 Features

- ✅ DNS Lookup
- ✅ WHOIS Lookup (with Python fallback)
- ✅ Traceroute
- ✅ Email Enumeration using `theHarvester` (Baidu)
- ✅ Personal Data & Social Media Scraping
- ✅ IP Geolocation (via `ipinfo.io`)
- ✅ DNSRecon Integration
- ✅ Subdomain Enumeration via `Sublist3r`
- ✅ Output results to a clean, themed **HTML report**
- ✅ Automatically creates report directory if not existing

---

## 🖥️ Requirements

Make sure the following tools are installed (most come pre-installed in Kali):

```bash
sudo apt update
sudo apt install theharvester dnsrecon sublist3r traceroute whois curl
pip install python-whois
````

---

## 🚀 Usage

### 1. Clone or Download

```bash
git clone https://github.com/yourusername/footprinting-tool.git
cd footprinting-tool
```

### 2. Run the Script

```bash
python3 footprint_domain.py example.com
```

### 3. Save Output to Custom HTML File

```bash
python3 footprint_advanced.py example.com --output /home/kali/reports/example_report.html
```

---

## 📂 Output

The tool prints results in the terminal and generates a structured HTML report containing:

* Subdomains
* Emails
* DNS records
* Traceroute hops
* WHOIS data
* IP metadata
* and more...

Example output file:

```
/home/kali/reports/example_report.html
```

---


## 🤖 Author

**Arman Kumar**
Cybersecurity | OSINT | AI Security Projects
[GitHub](https://github.com/armank8000) | [LinkedIn](https://linkedin.com/in/arman-kumar8000)

---

## ⭐️ Show Your Support

If you found this tool useful, please ⭐️ the repo and share it with your team!

```


