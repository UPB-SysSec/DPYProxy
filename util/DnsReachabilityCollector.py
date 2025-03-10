# Determines and outputs the reachability of all DNS servers and circumvention methods's specified in DnsModeDeterminator.py
import time

# hack to add parent to pythonpath
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from modules.dns.DnsModeDeterminator import DnsModeDeterminator

TIMEOUT = 5
CENSORED_DOMAIN = "wikipedia.org"
MIN_RETRIES = 3
MAX_RETRIES = 20
ADD_SNI = True
RESTRICT_ADVERTISED = True
BLOCK_PAGE_IPS = False
# wikipedia ranges https://wikitech.wikimedia.org/wiki/IP_and_AS_allocations

WIKIMEDIA_RANGES = [
"185.15.56.0/22",
"91.198.174.0/24",
"195.200.68.0/24",
"193.46.90.0/24",
"198.35.26.0/23",
"208.80.152.0/22",
"103.102.166.0/24"]

IRAN_BLOCK_PAGES = [
    "10.10.34.34",
    "10.10.34.35",
    "10.10.34.36"
]

def main():
    _det = DnsModeDeterminator(timeout=TIMEOUT,
                               censored_domain=CENSORED_DOMAIN,
                               compare_ip_ranges=WIKIMEDIA_RANGES,
                               block_page_ips=BLOCK_PAGE_IPS,
                               restrict_advertised=RESTRICT_ADVERTISED)

    print("Generating working resolvers... might take a while!")
    _time = time.time()

    for resolver in [x for x in _det.generate_working_resolver(min_retries=MIN_RETRIES, max_retries=MAX_RETRIES, add_sni=ADD_SNI)]:
        print(resolver)

    print(f"Time taken: {format_time(time.time() - _time)}")

def format_time(unix_timestamp: float) -> str:
    """
    Formats unix timestamp to hh:mm:ss format
    """
    return time.strftime('%H:%M:%S', time.gmtime(unix_timestamp))

if __name__ == "__main__":
    main()