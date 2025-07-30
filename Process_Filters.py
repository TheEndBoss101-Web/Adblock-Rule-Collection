import datetime
import pytz
import re

# === Common setup ===
tz = pytz.timezone('America/Chicago')
timestamp = datetime.datetime.now(tz).strftime('%Y-%m-%d %H:%M:%S')

dns_domain_regex = re.compile(
    r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$'
)

input_file = 'ADBLOCK_RULE_COLLECTION.txt'

def read_rules():
    with open(input_file, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

rules = read_rules()

# === Header writing ===
def write_file(filename, title, count, body_lines, prefix='', format='hash'):
    if format == 'adblock':
        header = f"""!Title: {title}
!Description: A DNS filter subscription summarizing multiple ad filtering rules, updated every 20 minutes to ensure timely synchronization with upstream filters and reduce false positives.
!Homepage: https://github.com/TheEndBoss101-Web/Adblock-Rule-Collection
!LICENSE1: https://github.com/TheEndBoss101-Web/Adblock-Rule-Collection/blob/master/LICENSE-GPL 3.0
!LICENSE2: https://github.com/TheEndBoss101-Web/Adblock-Rule-Collection/blob/master/LICENSE-CC-BY-NC-SA 4.0
!This code is based on https://github.com/REIJI007/Adblock-Rule-Collection/
!Generation Time: {timestamp}
!Valid Rule Count: {count}
"""
    else:
        header = f"""#Title: {title}
#Description: A list of domains collected from multiple adblock filter rules, updated every 20 minutes to ensure real-time synchronization with upstream sources and reduce false positives.
#Homepage: https://github.com/TheEndBoss101-Web/Adblock-Rule-Collection
#LICENSE1: https://github.com/TheEndBoss101-Web/Adblock-Rule-Collection/blob/master/LICENSE-GPL 3.0
#LICENSE2: https://github.com/TheEndBoss101-Web/Adblock-Rule-Collection/blob/master/LICENSE-CC-BY-NC-SA 4.0
#This code is based on https://github.com/REIJI007/Adblock-Rule-Collection/
#Generation Time: {timestamp}
#Valid Rule Count: {count}
"""

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(header + '\n')
        for line in body_lines:
            f.write(prefix + line + '\n')

    print(f"Generated {filename} with {count} entries.")

# === DNS Filter ===
dns_rules = []
for line in rules:
    match = re.match(r'^(\@\@)?\|\|([a-zA-Z0-9.-]+)\^$', line)
    if match:
        domain = match.group(2)
        if dns_domain_regex.match(domain):
            dns_rules.append(line)

write_file(
    "ADBLOCK_RULE_COLLECTION_DNS.txt",
    "Adblock-Rule-Collection-DNS",
    len(dns_rules),
    dns_rules,
    format='adblock'
)

# === Domain Filter ===
domain_rules = []
for line in rules:
    match = re.match(r'^\|\|([a-zA-Z0-9.-]+)\^$', line)
    if match:
        domain = match.group(1)
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', domain) and dns_domain_regex.match(domain):
            domain_rules.append(domain)

write_file(
    "ADBLOCK_RULE_COLLECTION_DOMAIN.txt",
    "Adblock-Rule-Collection-Domain",
    len(domain_rules),
    domain_rules
)

# === IPv4 Host File ===
ipv4_rules = [f"0.0.0.0 {domain}" for domain in domain_rules]
write_file(
    "ADBLOCK_RULE_COLLECTION_HOST_IPV4.txt",
    "Adblock-Rule-Collection-Host-IPv4",
    len(ipv4_rules),
    ipv4_rules
)

# === IPv6 Host File ===
ipv6_rules = [f":: {domain}" for domain in domain_rules]
write_file(
    "ADBLOCK_RULE_COLLECTION_HOST_IPV6.txt",
    "Adblock-Rule-Collection-Host-IPv6",
    len(ipv6_rules),
    ipv6_rules
)
