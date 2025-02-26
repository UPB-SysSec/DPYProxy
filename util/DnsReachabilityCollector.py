# Determines and outputs the reachability of all DNS servers and circumvention methods's specified in DnsModeDeterminator.py
import time

# hack to add parent to pythonpath
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from modules.dns.DnsModeDeterminator import DnsModeDeterminator

TIMEOUT = 5
CENSORED_DOMAIN = "wikipedia.org"
RETRIES = 10
# wikipedia ranges https://wikitech.wikimedia.org/wiki/IP_and_AS_allocations

WIKIMEDIA_RANGES = [
"185.15.56.0/22",
"91.198.174.0/24",
"195.200.68.0/24",
"193.46.90.0/24",
"198.35.26.0/23",
"208.80.152.0/22",
"103.102.166.0/24"]

def main():
    _det = DnsModeDeterminator(timeout=TIMEOUT,
                               censored_domain=CENSORED_DOMAIN,
                               censored_domain_ip_ranges=WIKIMEDIA_RANGES)

    print("Generating working resolvers... might take a while!")
    _time = time.time()

    # TODO: Remove / Add SNI based on flag
    for resolver in [x for x in _det.generate_working_resolver(retries=RETRIES)]:
        print(resolver)

    print(f"Time taken: {format_time(time.time() - _time)}")

def format_time(unix_timestamp: float) -> str:
    """
    Formats unix timestamp to hh:mm:ss format
    """
    return time.strftime('%H:%M:%S', time.gmtime(unix_timestamp))

if __name__ == "__main__":
    main()