import argparse
import os
import socket
import subprocess
import re
from datetime import datetime

try:
    import whois
except ImportError:
    whois = None

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Footprinting Report - {domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #111; color: #eee; padding: 20px; }}
        h1 {{ color: #0f0; }}
        pre {{ background: #222; padding: 10px; border-radius: 5px; overflow-x: auto; }}
        .section {{ margin-bottom: 30px; }}
    </style>
</head>
<body>
    <h1>Footprinting Report for {domain}</h1>
    {sections}
</body>
</html>
"""

SECTION_TEMPLATE = """
<div class="section">
    <h2>{title}</h2>
    <pre>{content}</pre>
</div>
"""

def run_command(command):
    try:
        return subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL).decode()
    except subprocess.CalledProcessError:
        return f"[!] Failed to run: {command}"

def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "N/A"

def dns_lookup(domain):
    return run_command(f"nslookup {domain}")

def traceroute_domain(domain):
    return run_command(f"traceroute {domain}")

def whois_lookup(domain):
    result = run_command(f"whois {domain}")
    if "No match" in result or len(result.strip()) < 20:
        if whois:
            try:
                w = whois.whois(domain)
                return str(w)
            except Exception as e:
                return "[!] WHOIS failed: " + str(e)
        else:
            return "[!] WHOIS failed. Install python-whois."
    return result

def email_enum(domain):
    result = run_command(f"theHarvester -d {domain} -b baidu -l 20")
    emails = re.findall(r'[\w\.-]+@[\w\.-]+', result)
    return "\n".join(set(emails)) if emails else "No emails found."

def personal_data_scrape(domain):
    result = run_command(f"theHarvester -d {domain} -b baidu -l 30")
    names = re.findall(r"Name: (.+)", result)
    social = re.findall(r"(https?:\/\/(?:www\.)?(?:twitter|linkedin|facebook|instagram)[^\s]+)", result)
    emails = re.findall(r'[\w\.-]+@[\w\.-]+', result)
    output = ""

    if names:
        output += "Names:\n" + "\n".join(set(names)) + "\n\n"
    if social:
        output += "Social Media:\n" + "\n".join(set(social)) + "\n\n"
    if emails:
        output += "Emails:\n" + "\n".join(set(emails)) + "\n"

    return output if output else "No personal data found."

def ip_info(ip):
    return run_command(f"curl -s https://ipinfo.io/{ip}/json")

def dns_recon(domain):
    return run_command(f"dnsrecon -d {domain}")

def subdomain_enum(domain):
    print(f"[~] Running Sublist3r for {domain}...")
    output = run_command(f"sublist3r -d {domain} -n -t 10")
    subdomains = re.findall(r'\b(?:[a-z0-9]+(?:[-.][a-z0-9]+)*\.)+' + re.escape(domain), output)
    return "\n".join(sorted(set(subdomains))) if subdomains else "No subdomains found."

def extract_info(domain):
    ip = get_ip(domain)
    return {
        "Domain": domain,
        "IP Address": ip,
        "DNS Lookup": dns_lookup(domain),
        "Traceroute": traceroute_domain(domain),
        "WHOIS Record": whois_lookup(domain),
        "Email Enumeration (Baidu)": email_enum(domain),
        "Personal Data Gathering": personal_data_scrape(domain),
        "IP Geolocation": ip_info(ip),
        "DNSRecon Results": dns_recon(domain),
        "Subdomain Enumeration": subdomain_enum(domain)
    }

def generate_html(data):
    domain = data["Domain"]
    sections = ""
    for title, content in data.items():
        if title == "Domain":
            continue
        sections += SECTION_TEMPLATE.format(title=title, content=content)
    return HTML_TEMPLATE.format(domain=domain, sections=sections)

def sanitize_filename(filename):
    return re.sub(r'[^\w\-./]', '_', filename)

def save_html(filepath, content):
    filepath = sanitize_filename(filepath)
    try:
        folder = os.path.dirname(filepath)
        if folder and not os.path.exists(folder):
            os.makedirs(folder)
        with open(filepath, "w") as f:
            f.write(content)
        print(f"[+] HTML report saved at: {filepath}")
    except Exception as e:
        print(f"[!] Failed to save report: {e}")

def main():
    parser = argparse.ArgumentParser(description="🔎 Advanced Domain Footprinting Tool (Kali Linux)")
    parser.add_argument("domain", help="Target domain name")
    parser.add_argument("-o", "--output", metavar="FILE", help="Save HTML report to a specific file")
    args = parser.parse_args()

    print(f"\n[+] Gathering data for: {args.domain}")
    data = extract_info(args.domain)

    for k, v in data.items():
        if k not in ["Domain", "IP Address"]:
            print(f"\n[+] {k}\n{'-'*40}\n{v}")

    html = generate_html(data)
    if args.output:
        save_html(args.output, html)
    else:
        default_file = f"{args.domain}_report.html"
        save_html(default_file, html)

if __name__ == "__main__":
    main()

