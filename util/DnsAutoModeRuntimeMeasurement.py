import logging
import statistics

# hack to add parent to pythonpath
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from enumerators.DnsProxyMode import DnsProxyMode
from modules.dns.DnsProxy import DnsProxy
from network.NetworkAddress import NetworkAddress

WIKIMEDIA_RANGES = [
"185.15.56.0/22",
"91.198.174.0/24",
"195.200.68.0/24",
"193.46.90.0/24",
"198.35.26.0/23",
"208.80.152.0/22",
"103.102.166.0/24"]

test_amount = 100
startup_times = []
for i in range(test_amount):
    server_address = NetworkAddress("localhost", 4433)
    resolver_address = NetworkAddress(None, 4433)

    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

    proxy = DnsProxy(proxy_mode=DnsProxyMode.AUTO,
                                  address=server_address,
                                  timeout=3,
                                  dns_resolver_address=resolver_address,
                                  censored_domain="wikipedia.org",
                                  censored_domain_ip_ranges=WIKIMEDIA_RANGES,
                                  add_sni=True)

    startup_time = proxy.start(time_measurement_only=True)
    startup_times.append(startup_time)

# Basic statistics
average = statistics.mean(startup_times)
median = statistics.median(startup_times)
minimum = min(startup_times)
maximum = max(startup_times)
stdev = statistics.stdev(startup_times)  # Sample standard deviation

# Print summary
print("========= Timing Statistics =========")
print(f"Count:   {len(startup_times)}")
print(f"Average: {average:.2f} seconds")
print(f"Median:  {median:.2f} seconds")
print(f"Min:     {minimum:.2f} seconds")
print(f"Max:     {maximum:.2f} seconds")
print(f"Stdev:   {stdev:.2f} seconds")