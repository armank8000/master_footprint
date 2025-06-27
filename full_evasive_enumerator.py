# full_evasive_enumerator.py

import os
import argparse
import re

HTML_HEAD = """
<html><head><title>Full Enumeration Report</title>
<style>
body { background:#111; color:#0f0; font-family:monospace; padding:20px; }
details { margin-bottom: 15px; border: 1px solid #0f0; padding: 10px; background-color: #000; }
details summary { cursor: pointer; font-weight: bold; color: #0ff; }
pre { white-space: pre-wrap; word-wrap: break-word; }
footer { margin-top:50px; font-size:small; color:#555; border-top:1px solid #444; padding-top:10px; }
</style></head><body><h1>🚀 Advanced Firewall-Evading Enumeration Report</h1>
"""
HTML_FOOT = """
<footer>
🔒 Script maintained by <strong>Arman Kumar</strong> | GitHub: <a href='https://github.com/armank8000' style='color:#0ff;' target='_blank'>armank8000</a>
</footer></body></html>"""

def run_cmd(cmd):
    print(f"\n[+] Running: {cmd}")
    return os.popen(cmd).read()

def build_evasion_flags():
    return "-Pn -T2 -f --data-length 25 --source-port 53 --spoof-mac 0 -D RND:10"

def analyze_results(results):
    analysis = []
    def suggest(tool, description, exploit):
        return f"\n➡️ {description}\n🔧 Suggested Tool: {tool}\n💣 Exploit/Technique: {exploit}\n"

    for key, output in results.items():
        if "SMB Shares" in key and "\"IPC$\"" in output:
            analysis.append(suggest("smbclient / enum4linux",
                                    "SMB open shares detected. Potential for null session exploitation.",
                                    "Metasploit: auxiliary/scanner/smb/smb_enumshares"))
        if "SNMP" in key and "SNMPv2" in output:
            analysis.append(suggest("snmp-check / snmpwalk",
                                    "SNMP v2c exposed. Default community strings may be guessable.",
                                    "Metasploit: auxiliary/scanner/snmp/snmp_enum"))
        if "NFS Shares" in key and "/" in output:
            analysis.append(suggest("showmount / mount",
                                    "Public NFS share exposed.",
                                    "Manual Exploit: mount NFS share and extract sensitive data"))
        if "VoIP" in key and "SIP" in output:
            analysis.append(suggest("svmap / svwar",
                                    "SIP service detected.",
                                    "Metasploit: auxiliary/scanner/sip/sip_enum"))
        if "IPSec" in key and "IKE Version" in output:
            analysis.append(suggest("ike-scan",
                                    "IKE VPN fingerprinting.",
                                    "Metasploit: auxiliary/scanner/ike/ikeenum"))
        if "SMTP" in key and "VRFY" in output:
            analysis.append(suggest("smtp-user-enum",
                                    "SMTP user enumeration via VRFY/EXPN.",
                                    "Metasploit: auxiliary/scanner/smtp/smtp_enum"))
        if "LDAP" in key and "dn:" in output:
            analysis.append(suggest("ldapsearch",
                                    "Anonymous LDAP bind allows enumeration.",
                                    "Metasploit: auxiliary/gather/ldap_search"))
        if "DNS Enum" in key and "recursion" in output:
            analysis.append(suggest("dnsenum / dig",
                                    "DNS server misconfigured (zone transfer or recursion).",
                                    "Metasploit: auxiliary/gather/dns_info"))
        if "SMB Users" in key and "guest" in output.lower():
            analysis.append(suggest("enum4linux",
                                    "SMB guest account present.",
                                    "Metasploit: auxiliary/scanner/smb/smb_enumusers"))
    if not analysis:
        analysis.append("No critical enumeration vulnerabilities detected based on available scripts.")
    return "\n".join(analysis)

def enumerate_host(ip):
    evasive = build_evasion_flags()
    results = {}

    def both(title, nmap_cmd, tool_cmd):
        results[f"{title} (Nmap)"] = run_cmd(f"{nmap_cmd} {ip}")
        results[f"{title} (Tool)"] = run_cmd(f"{tool_cmd} {ip}")

    results["Nmap Full Scan"] = run_cmd(f"nmap -sS -sV -O -A {evasive} {ip}")
    both("NetBIOS", f"nmap -p 137 --script nbstat {evasive}", "nbtscan")
    both("SMB Shares", f"nmap -p 445 --script smb-enum-shares {evasive}", "smbclient -L \\{ip} -N")
    both("SMB Users", f"nmap -p 445 --script smb-enum-users {evasive}", "enum4linux")
    both("SNMP", f"nmap -sU -p 161 --script snmp-info {evasive}", "snmpwalk -v2c -c public")
    both("LDAP", f"nmap -p 389 --script ldap-search {evasive}", "ldapsearch -x -H ldap://")
    both("RPC Services", f"nmap -p 111 --script rpcinfo {evasive}", "rpcinfo -p")
    both("NFS Shares", f"nmap -p 2049 --script nfs-showmount {evasive}", "showmount -e")
    both("NTP Info", f"nmap -sU -p 123 --script ntp-info {evasive}", "ntpq -p")
    both("SMTP Enum", f"nmap -p 25 --script smtp-enum-users {evasive}", "smtp-user-enum -M VRFY -U /usr/share/wordlists/usernames.txt -t")
    both("DNS Enum", f"nmap -p 53 --script dns-recursion,dns-service-discovery,dns-nsid {evasive}", "dnsenum")
    both("VoIP (SIP)", f"nmap -sU -p 5060 --script sip-methods {evasive}", "svmap")
    both("IPSec (IKE)", f"nmap -sU -p 500 --script ike-version {evasive}", "ike-scan")

    results["Attack Surface Analysis"] = analyze_results(results)
    return results

def discover_hosts(subnet):
    evasive = build_evasion_flags()
    print(f"[~] Discovering hosts in {subnet}...")
    out = run_cmd(f"nmap -n -sS {evasive} -oG - {subnet}")
    return [line.split()[1] for line in out.splitlines() if line.startswith("Host:") and "Ports:" in line]

def save_html(outfile, sections):
    with open(outfile, 'w') as f:
        f.write(HTML_HEAD)
        for title, data in sections.items():
            f.write(f"<details><summary>{title}</summary><pre>{data}</pre></details>")
        f.write(HTML_FOOT)
    print(f"[✔] Output saved to {outfile}")

def main():
    parser = argparse.ArgumentParser(description="🔥 Full Evasive Enumerator")
    parser.add_argument("-i", "--ip", required=True, help="Target IP or subnet (e.g. 192.168.1.0/24)")
    parser.add_argument("-o", "--output", help="Optional output HTML file")
    args = parser.parse_args()

    hosts = discover_hosts(args.ip)
    all_results = {}

    for host in hosts:
        print(f"\n[🔍] Enumerating {host}...")
        host_results = enumerate_host(host)
        for k, v in host_results.items():
            all_results[f"{host} - {k}"] = v

    if args.output:
        save_html(args.output, all_results)
    else:
        for k, v in all_results.items():
            print(f"\n==== {k} ====\n{v}")

if __name__ == "__main__":
    main()
