import os
# hack to add parent to pythonpath
import sys

from dns.message import make_query

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from enumerators.DnsProxyMode import DnsProxyMode
from enumerators.DnsResolvers import DnsResolvers
from network.DomainResolver import DomainResolver
from network.NetworkAddress import NetworkAddress
from util.Util import parse_all_ips

TIMEOUT = 5

def main():
    local_address = NetworkAddress("127.0.0.53", 53)
    local_resolver = DomainResolver(DnsProxyMode.UDP, local_address, TIMEOUT, "")
    for resolver in DnsResolvers:
        if resolver.hostname == "":
            continue # No need to test Gcore

        message = make_query(resolver.hostname, "A")
        try:
            answer = local_resolver.resolve_udp_static(message, resolver=local_address, timeout=TIMEOUT)
            resolved_ips = parse_all_ips(answer)
            if resolver.value not in resolved_ips:
                print(f"Ip mismatch between {resolver} and {resolved_ips}")
        except Exception as e:
            print(f"Could not determine IP of {resolver} due to {e}")

main()