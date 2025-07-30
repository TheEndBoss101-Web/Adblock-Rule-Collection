import re

input_file = 'ADBLOCK_RULE_COLLECTION.txt'

# Regular expressions
adblock_entry = re.compile(r'^\|\|(.+?)\^$')
ipv4_regex = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
ipv6_regex = re.compile(r'^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$')

domains = []
ipv4s = []
ipv6s = []

# Read and classify entries
with open(input_file, 'r', encoding='utf-8') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        match = adblock_entry.match(line)
        if not match:
            continue

        value = match.group(1)

        if ipv4_regex.match(value):
            ipv4s.append(value)
        elif ipv6_regex.match(value):
            ipv6s.append(value)
        else:
            domains.append(value)

# Write output files with no headers
with open('ADBLOCK_RULE_COLLECTION_RAW_DOMAIN.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(domains) + '\n')

with open('ADBLOCK_RULE_COLLECTION_RAW_IPV4.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(ipv4s) + '\n')

with open('ADBLOCK_RULE_COLLECTION_RAW_IPV6.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(ipv6s) + '\n')

print(f"Wrote {len(domains)} domains, {len(ipv4s)} IPv4s, {len(ipv6s)} IPv6s.")
