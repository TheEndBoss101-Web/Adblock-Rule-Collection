import os
import sys
import subprocess
import warnings
import importlib.util
import logging
import asyncio
import aiohttp
import re
import time
from urllib3.exceptions import InsecureRequestWarning
from datetime import datetime, timezone, timedelta
try:
    from lists import filter_urls, allowlist_urls
except ImportError as e:
    print(f"Missing or invalid configuration file: {e}")
    sys.exit(1)

# Logging configuration
logging.basicConfig(filename='adblock_rule_downloader.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def log_status(message, level="info"):
    print(message)
    if level == "info":
        logging.info(message)
    elif level == "warning":
        logging.warning(message)
    elif level == "error":
        logging.error(message)
    elif level == "debug":
        logging.debug(message)
    elif level == "critical":
        logging.critical(message)


def install_packages(packages):
    for package in packages:
        if importlib.util.find_spec(package) is None:
            log_status(f"Installing missing package: {package}")
            subprocess.run([sys.executable, "-m", "pip", "install", package], check=True)
            log_status(f"Installed: {package}")
        else:
            log_status(f"Package already installed: {package}")


required_packages = ["aiohttp", "urllib3", "certifi"]
install_packages(required_packages)

warnings.simplefilter('ignore', InsecureRequestWarning)


def is_valid_rule(line):
    line = line.strip()
    return bool(line and not line.startswith(('!', '#', '[', ';', '//', '/*', '*/')))


def is_ip_domain_mapping(line):
    return re.match(r'^\d{1,3}(\.\d{1,3}){3}\s+\S+', line) is not None


def is_ip_address(line):
    return re.match(r'^\d{1,3}(\.\d{1,3}){3}$', line) is not None


def is_ipv6_domain_mapping(line):
    return re.match(r'^[\da-fA-F:]+\s+\S+', line) is not None


def is_ipv6_address(line):
    return re.match(r'^[\da-fA-F:]+$', line) is not None


def is_domain(line):
    return re.match(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', line) is not None


def process_line(line):
    line = line.strip()
    if not is_valid_rule(line):
        return None

    if line.startswith('0.0.0.0') or line.startswith('127.0.0.1'):
        parts = line.split()
        if len(parts) >= 2:
            domain = parts[1].split('#')[0].strip()
            return f"||{domain}^"

    if line.startswith('::') or line.startswith('::1'):
        parts = line.split()
        if len(parts) >= 2:
            domain = parts[1].split('#')[0].strip()
            return f"||{domain}^"

    if is_ip_domain_mapping(line) or is_ipv6_domain_mapping(line):
        return None

    if is_ip_address(line) or is_ipv6_address(line):
        return f"||{line}^"

    if line.startswith('address='):
        parts = line.split('=')
        if len(parts) == 3:
            domain = parts[1].strip()
            target_ip = parts[2].strip()
            if target_ip in ['127.0.0.1', '0.0.0.0', '::1', '::']:
                return f"||{domain}^"

    elif line.startswith('server='):
        parts = line.split('=', 1)
        if len(parts) == 2:
            server_info = parts[1].split('/')
            if len(server_info) == 3:
                domain = server_info[1].strip()
                target_ip = server_info[2].strip()
                if target_ip in ['127.0.0.1', '0.0.0.0', '::1', '::']:
                    return f"||{domain}^"

    if is_domain(line):
        return f"||{line}^"

    return line


def normalize_domain_entry(line):
    line = line.strip()
    if line.startswith('@@||') and line.endswith('^'):
        return line[4:-1]
    if line.startswith('||') and line.endswith('^'):
        return line[2:-1]
    if line.startswith(('0.0.0.0', '127.0.0.1', '::', '::1')):
        parts = line.split()
        if len(parts) >= 2:
            return parts[1].strip()
    if is_domain(line):
        return line
    return None


async def download_filter(session, url, retries=5):
    rules = set()
    attempt = 0
    while attempt < retries:
        try:
            log_status(f"Downloading: {url} (Attempt {attempt + 1})")
            async with session.get(url, ssl=False) as response:
                if response.status == 200:
                    log_status(f"Downloaded successfully: {url}")
                    text = await response.text()
                    lines = text.splitlines()
                    for line in lines:
                        if is_valid_rule(line):
                            processed_line = process_line(line)
                            if processed_line is not None:
                                rules.add(processed_line)
                    break
                else:
                    log_status(f"Failed to download {url} (Status {response.status})", level="error")
        except Exception as e:
            log_status(f"Error downloading {url}: {e}", level="error")
        attempt += 1
        if attempt < retries:
            wait_time = 2 ** attempt
            log_status(f"Retrying {url} in {wait_time} seconds...")
            await asyncio.sleep(wait_time)
        else:
            log_status(f"Max retries reached for {url}", level="error")
    return rules


async def download_filters(urls):
    log_status("Beginning asynchronous rule downloads...")
    async with aiohttp.ClientSession() as session:
        tasks = [download_filter(session, url) for url in urls]
        all_rules = set()
        for future in asyncio.as_completed(tasks):
            rules = await future
            all_rules.update(rules)
    log_status(f"Finished downloading. Total unique rules collected: {len(all_rules)}")
    return all_rules


async def download_plain_list(session, url, as_whitelist=False):
    domains = set()
    try:
        log_status(f"Downloading {'allowlist' if as_whitelist else 'list'}: {url}")
        async with session.get(url, ssl=False) as response:
            if response.status == 200:
                text = await response.text()
                lines = text.splitlines()
                for line in lines:
                    domain = normalize_domain_entry(line)
                    if domain:
                        if as_whitelist:
                            domains.add(f"@@||{domain}^")
                        else:
                            domains.add(domain)
            else:
                log_status(f"Failed to download {url} (Status {response.status})", level="error")
    except Exception as e:
        log_status(f"Error downloading {url}: {e}", level="error")
    return domains


def validate_rules(rules):
    log_status("Validating and deduplicating rules...")
    validated_rules = set()
    for rule in rules:
        if is_valid_rule(rule):
            validated_rules.add(rule)
    log_status(f"Validation complete. {len(validated_rules)} valid rules remain.")
    return validated_rules


def write_rules_to_file(rules, save_path):
    now = datetime.now(timezone(timedelta(hours=-5)))
    timestamp = now.strftime('%Y-%m-%d %H:%M:%S %Z')
    header = f"""
!Title: Adblock Collection
!Description: An ad filter subscription that summarizes multiple ad-blocking filter rules, updated every 20 minutes to ensure timely synchronization with upstream to reduce false positives.
!Homepage: https://github.com/TheEndBoss101-Web/Adblock-Rule-Collection
!LICENSE1: https://github.com/TheEndBoss101-Web/Adblock-Rule-Collection/blob/main/LICENSE-GPL 3.0
!LICENSE2: https://github.com/TheEndBoss101-Web/Adblock-Rule-Collection/blob/main/LICENSE-CC-BY-NC-SA 4.0
!This code is based on https://github.com/REIJI007/Adblock-Rule-Collection/
!Generated on: {timestamp}
!Number of valid rules: {len(rules)}
"""
    log_status(f"Writing rules to file: {save_path}")
    with open(save_path, 'w', encoding='utf-8') as f:
        f.write(header)
        f.write('\n')
        f.writelines(f"{rule}\n" for rule in sorted(rules) if rule is not None)
    log_status(f"File written: {save_path}")
    log_status(f"Total rules saved: {len(rules)}")


async def main_async():
    log_status("=== Adblock Rule Downloader Started ===")

    save_path = os.path.join(os.getcwd(), 'ADBLOCK_RULE_COLLECTION.txt')

    async with aiohttp.ClientSession() as session:
        raw_rules = await download_filters(filter_urls)

        allowlist = set()
        for url in allowlist_urls:
            allowlist.update(await download_plain_list(session, url, as_whitelist=True))

    final_rules = raw_rules.union(allowlist)
    validated_rules = validate_rules(final_rules)
    write_rules_to_file(validated_rules, save_path)

    log_status("=== All tasks completed ===")


def main():
    asyncio.run(main_async())
    if sys.stdin.isatty():
        input("Press Enter to exit...")
    else:
        log_status("Non-interactive mode, exiting...")


if __name__ == '__main__':
    main()
