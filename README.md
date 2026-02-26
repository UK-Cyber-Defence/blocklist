📖 About
UK Cyber Defence operates a distributed network of honeypots and deception devices deployed across multiple regions and cloud providers. Every interaction with these systems is, by definition, unsolicited and malicious — there is no legitimate reason for any host to connect to them. This repository publishes the IP addresses and network ranges captured by that infrastructure as free, open blocklists that anyone can use to harden their own environments.
All timestamps and scheduling are in UTC.

🎯 What We Detect
| Category | Description |
| --- | --- |
|Mass Scanners|Hosts performing indiscriminate port sweeps and service enumeration across wide IP ranges.|
|Brute-Force Actors|IPs attempting credential-stuffing and password-spraying attacks against SSH, RDP, SMTP, and other authentication services.|
|Exploit Probes|Systems actively probing for known CVEs, zero-days, and misconfigurations in web applications, APIs, and network services.|
|Botnet Infrastructure|Command-and-control nodes, loader/dropper sources, and compromised hosts participating in botnet activity.|
|Web Application Attacks|SQL injection, XSS, path traversal, remote file inclusion, and other OWASP Top 10 attack patterns.|
|Tor Exit Node Abuse|Tor exit nodes observed conducting active attacks (not listed merely for being Tor exits).|

📂 Repository Structure
blocklist/
├── lists/
│   ├── ipv4-attackers.txt        # IPv4 addresses of confirmed attackers
│   ├── ipv4-scanners.txt         # IPv4 addresses of mass scanners
│   ├── ipv4-bruteforce.txt       # IPv4 addresses of brute-force actors
│   ├── ipv4-combined.txt         # All IPv4 threats combined & deduplicated
│   ├── ipv6-attackers.txt        # IPv6 addresses of confirmed attackers
│   ├── ipv6-combined.txt         # All IPv6 threats combined & deduplicated
│   └── cidr-aggregated.txt       # CIDR-aggregated network ranges
├── formats/
│   ├── iptables.rules            # Ready-to-import iptables rules
│   ├── nftables.conf             # nftables configuration
│   ├── nginx-deny.conf           # NGINX deny directives
│   ├── apache-deny.conf          # Apache 2.4 Require not ip directives
│   ├── pf.txt                    # OpenBSD PF table format
│   └── mikrotik.rsc              # MikroTik RouterOS script
├── archive/                      # Historical snapshots (YYYY-MM-DD)
├── LICENCE
├── CONTRIBUTING.md
└── README.md

Note: The above is a recommended structure. Check the repository root for the actual files currently published.


🚀 Quick Start
Download the Latest Combined Blocklist
bashcurl -sSL https://raw.githubusercontent.com/UK-Cyber-Defence/blocklist/main/lists/ipv4-combined.txt -o /tmp/ukcd-blocklist.txt
iptables (Linux)
bash# Create a dedicated chain
sudo iptables -N UKCD_BLOCKLIST

# Populate from the list
while IFS= read -r ip; do
    [[ "$ip" =~ ^#.*$ || -z "$ip" ]] && continue
    sudo iptables -A UKCD_BLOCKLIST -s "$ip" -j DROP
done < /tmp/ukcd-blocklist.txt

# Attach to INPUT and FORWARD chains
sudo iptables -I INPUT 1 -j UKCD_BLOCKLIST
sudo iptables -I FORWARD 1 -j UKCD_BLOCKLIST
nftables (Linux)
bashsudo nft add set inet filter ukcd_blocklist { type ipv4_addr\; flags interval\; }
while IFS= read -r ip; do
    [[ "$ip" =~ ^#.*$ || -z "$ip" ]] && continue
    sudo nft add element inet filter ukcd_blocklist { "$ip" }
done < /tmp/ukcd-blocklist.txt
ipset + iptables (Recommended for Large Lists)
bashsudo ipset create ukcd-blocklist hash:net maxelem 1000000
while IFS= read -r ip; do
    [[ "$ip" =~ ^#.*$ || -z "$ip" ]] && continue
    sudo ipset add ukcd-blocklist "$ip" -exist
done < /tmp/ukcd-blocklist.txt

sudo iptables -I INPUT -m set --match-set ukcd-blocklist src -j DROP
sudo iptables -I FORWARD -m set --match-set ukcd-blocklist src -j DROP
Apache 2.4
apache# In your VirtualHost or .htaccess
<RequireAll>
    Require all granted
    Include /etc/apache2/conf-available/ukcd-blocklist.conf
</RequireAll>
NGINX
nginx# /etc/nginx/conf.d/ukcd-blocklist.conf
# Include in your server block:
#   include /etc/nginx/conf.d/ukcd-blocklist.conf;
# Each line: deny <ip>;
Fail2Ban Integration
ini# /etc/fail2ban/action.d/ukcd-blocklist.conf
[Definition]
actionban = ipset add ukcd-blocklist <ip> -exist
actionunban = ipset del ukcd-blocklist <ip> -exist
pfSense / OPNsense
Navigate to Firewall → Aliases → URLs and add:
https://raw.githubusercontent.com/UK-Cyber-Defence/blocklist/main/lists/ipv4-combined.txt
Set the type to URL Table (IPs) and assign a refresh interval.
MikroTik RouterOS
routeros/tool fetch url="https://raw.githubusercontent.com/UK-Cyber-Defence/blocklist/main/formats/mikrotik.rsc" dst-path=ukcd-blocklist.rsc
/import file-name=ukcd-blocklist.rsc

🔄 Automated Updates
The blocklists are updated regularly. We strongly recommend automating your ingestion with a cron job or systemd timer.
Cron Example (Updates Daily at 04:00 UTC)
bash# /etc/cron.d/ukcd-blocklist
0 4 * * * root /opt/ukcd-blocklist/update.sh >> /var/log/ukcd-blocklist.log 2>&1
Sample Update Script
bash#!/usr/bin/env bash
# /opt/ukcd-blocklist/update.sh
set -euo pipefail

BLOCKLIST_URL="https://raw.githubusercontent.com/UK-Cyber-Defence/blocklist/main/lists/ipv4-combined.txt"
DEST="/etc/ukcd-blocklist/ipv4-combined.txt"
IPSET_NAME="ukcd-blocklist"

# Download with integrity check
TMP=$(mktemp)
curl -sSfL "$BLOCKLIST_URL" -o "$TMP" || { echo "[ERROR] Download failed"; exit 1; }

# Validate — ensure the file is not empty and contains IPs
if [[ ! -s "$TMP" ]] || ! grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$TMP"; then
    echo "[ERROR] Downloaded file appears invalid"
    rm -f "$TMP"
    exit 1
fi

mv "$TMP" "$DEST"
chmod 644 "$DEST"

# Rebuild ipset atomically
ipset create "${IPSET_NAME}-tmp" hash:net maxelem 1000000
while IFS= read -r ip; do
    [[ "$ip" =~ ^#.*$ || -z "$ip" ]] && continue
    ipset add "${IPSET_NAME}-tmp" "$ip" -exist
done < "$DEST"

ipset swap "${IPSET_NAME}-tmp" "$IPSET_NAME"
ipset destroy "${IPSET_NAME}-tmp"

echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] Blocklist updated — $(grep -cvE '^(#|$)' "$DEST") entries loaded"

📋 List Format
All plain-text lists follow a consistent format:
# UK Cyber Defence Blocklist
# Category: Combined Threats
# Generated: 2025-06-15T04:00:00Z
# Entries: 48372
# Licence: See repository LICENCE file
# Contact: https://github.com/UK-Cyber-Defence/blocklist/issues
#
# One IP address or CIDR range per line.
# Lines beginning with # are comments.

1.2.3.4
5.6.7.0/24
198.51.100.42
...

🔒 Data Integrity & Methodology
Collection: All data originates from purpose-built honeypots and deception devices that serve no legitimate function. Any connection to these systems constitutes unsolicited, hostile activity.
Validation: Raw captures pass through a multi-stage pipeline before publication:

Deduplication — Redundant entries are collapsed.
Whitelisting — Known legitimate scanners (e.g., Shodan, Censys, where explicitly opted-in by the operator) and major CDN/cloud egress ranges are excluded to minimise false positives.
Threshold Filtering — Single-packet anomalies are discarded; only hosts exhibiting sustained or repeated malicious behaviour are listed.
CIDR Aggregation — Where multiple IPs fall within the same allocation and exhibit the same behaviour, ranges are aggregated to reduce list size.
Expiry — Entries are automatically removed after a defined period of inactivity to keep the lists current.

False Positives: Whilst we take extensive measures to minimise false positives, no blocklist is infallible. If you believe a legitimate IP has been listed in error, please open an issue with evidence and we will investigate promptly.

⚠️ Responsible Use

Test before deploying to production. Import the blocklist into a staging environment or run in log-only mode before enforcing drops.
Monitor your logs. Watch for false positives, especially if you operate infrastructure that communicates with a wide range of hosts.
Combine, don't rely solely. This blocklist is one layer. Use it alongside rate limiting, intrusion detection systems, WAFs, and other defence-in-depth measures.
Respect proportionality. These lists are designed to block known-hostile sources, not to perform blanket geo-blocking.


🤝 Contributing
We welcome contributions from the community. Please see CONTRIBUTING.md for details on:

Reporting false positives or false negatives
Submitting additional threat intelligence
Proposing new list formats or integrations
Improving documentation


📡 Community & Support

Issues: GitHub Issues
Discussions: GitHub Discussions


📜 Licence
This project is provided free of charge for both personal and commercial use. Please refer to the LICENCE file in this repository for the full terms.

🏷️ Acknowledgements
This project is maintained by UK Cyber Defence and made possible by the collective effort of our honeypot operators, threat analysts, and the wider cyber security community.
If you find these blocklists useful, consider giving the repository a ⭐ — it helps others discover the project.
