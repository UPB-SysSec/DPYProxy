from unittest.mock import MagicMock, patch

from dns.message import make_query
from dns.rcode import NOERROR, SERVFAIL

from enumerators.DnsProxyMode import DnsProxyMode
from modules.dns.DnsModeDeterminator import DnsModeDeterminator
from modules.dns.DnsProxy import DnsProxy
from network.DomainResolver import DomainResolver
from network.NetworkAddress import NetworkAddress

IP_RANGES = [
    "8.8.4.0/24",
    "8.8.8.0/24",
    "8.34.208.0/20",
    "8.35.192.0/20",
    "23.236.48.0/20",
    "23.251.128.0/19",
    "34.0.0.0/15",
    "34.2.0.0/16",
    "34.3.0.0/23",
    "34.3.3.0/24",
    "34.3.4.0/24",
    "34.3.8.0/21",
    "34.3.16.0/20",
    "34.3.32.0/19",
    "34.3.64.0/18",
    "34.4.0.0/14",
    "34.8.0.0/13",
    "34.16.0.0/12",
    "34.32.0.0/11",
    "34.64.0.0/10",
    "34.128.0.0/10",
    "35.184.0.0/13",
    "35.192.0.0/14",
    "35.196.0.0/15",
    "35.198.0.0/16",
    "35.199.0.0/17",
    "35.199.128.0/18",
    "35.200.0.0/13",
    "35.208.0.0/12",
    "35.224.0.0/12",
    "35.240.0.0/13",
    "57.140.192.0/18",
    "64.15.112.0/20",
    "64.233.160.0/19",
    "66.22.228.0/23",
    "66.102.0.0/20",
    "66.249.64.0/19",
    "70.32.128.0/19",
    "72.14.192.0/18",
    "74.114.24.0/21",
    "74.125.0.0/16",
    "104.154.0.0/15",
    "104.196.0.0/14",
    "104.237.160.0/19",
    "107.167.160.0/19",
    "107.178.192.0/18",
    "108.59.80.0/20",
    "108.170.192.0/18",
    "108.177.0.0/17",
    "130.211.0.0/16",
    "136.22.160.0/20",
    "136.22.176.0/21",
    "136.22.184.0/23",
    "136.22.186.0/24",
    "136.124.0.0/15",
    "142.250.0.0/15",
    "146.148.0.0/17",
    "152.65.208.0/22",
    "152.65.214.0/23",
    "152.65.218.0/23",
    "152.65.222.0/23",
    "152.65.224.0/19",
    "162.120.128.0/17",
    "162.216.148.0/22",
    "162.222.176.0/21",
    "172.110.32.0/21",
    "172.217.0.0/16",
    "172.253.0.0/16",
    "173.194.0.0/16",
    "173.255.112.0/20",
    "192.104.160.0/23",
    "192.158.28.0/22",
    "192.178.0.0/15",
    "193.186.4.0/24",
    "199.36.154.0/23",
    "199.36.156.0/24",
    "199.192.112.0/22",
    "199.223.232.0/21",
    "207.223.160.0/20",
    "208.65.152.0/22",
    "208.68.108.0/22",
    "208.81.188.0/22",
    "208.117.224.0/19",
    "209.85.128.0/17",
    "216.58.192.0/19",
    "216.73.80.0/20",
    "216.239.32.0/19",
    "216.252.220.0/22",
]
DOMAIN = "www.google.dj"


def test_auto_mode_works():
    """
    Test that DnsModeDeterminator successfully selects a working resolver
    from potential candidate resolvers using the provided IP ranges and auto-detection.
    """
    resolver = DnsModeDeterminator(5, DOMAIN, IP_RANGES, False).generate_working_resolver().__next__()
    assert resolver is not None


def test_dns_proxy_resolve_message_success():
    """
    Test that DnsProxy correctly handles resolving a DNS message when the
    underlying domain resolver completes successfully.
    """
    proxy = DnsProxy(
        address=NetworkAddress("127.0.0.1", 5533),
        timeout=3,
        proxy_mode=DnsProxyMode.UDP,
        dns_resolver_address=NetworkAddress("8.8.8.8", 53),
        censored_domain="example.com",
        compare_ip_ranges=[],
        block_page_ips=False,
        add_sni=False,
    )

    proxy.domain_resolver = MagicMock()

    # Mock the resolve method to return a valid DNS response
    query = make_query("example.com", "A")
    response = make_query("example.com", "A")
    response.set_rcode(NOERROR)
    proxy.domain_resolver.resolve.return_value = response

    answer = proxy.resolve_message(query.to_wire(), NetworkAddress("127.0.0.1", 12345))

    assert answer is not None
    assert answer.rcode() == NOERROR
    proxy.domain_resolver.resolve.assert_called_once()


def test_dns_proxy_resolve_message_exception():
    """
    Test that DnsProxy returns a SERVFAIL response code if the domain resolver
    raises an exception.
    """
    proxy = DnsProxy(
        address=NetworkAddress("127.0.0.1", 5533),
        timeout=3,
        proxy_mode=DnsProxyMode.UDP,
        dns_resolver_address=NetworkAddress("8.8.8.8", 53),
        censored_domain="example.com",
        compare_ip_ranges=[],
        block_page_ips=False,
        add_sni=False,
    )

    proxy.domain_resolver = MagicMock()

    # Mock the resolve method to raise an Exception
    query = make_query("example.com", "A")
    proxy.domain_resolver.resolve.side_effect = Exception("Resolution failed")

    answer = proxy.resolve_message(query.to_wire(), NetworkAddress("127.0.0.1", 12345))

    assert answer is not None
    assert answer.rcode() == SERVFAIL
    proxy.domain_resolver.resolve.assert_called_once()


@patch("network.DomainResolver.udp")
def test_domain_resolver_resolve_static_udp(mock_udp):
    """
    Test that resolving a DNS query using static UDP method correctly forwards
    the request to the specified IP and port with appropriate timeout.
    """
    mock_udp.return_value = make_query("example.com", "A")
    query = make_query("example.com", "A")
    resolver_addr = NetworkAddress("8.8.8.8", 53)

    result = DomainResolver.resolve_static(mode=DnsProxyMode.UDP, message=query, resolver=resolver_addr, timeout=3)

    assert result is not None
    mock_udp.assert_called_once_with(query, where="8.8.8.8", port=53, timeout=3)


@patch("network.DomainResolver.tls")
def test_domain_resolver_resolve_static_dot(mock_tls):
    """
    Test that resolving a DNS query using static DNS-over-TLS method
    correctly configures and invokes the underlying TLS parameters (like hostname/SNI).
    """
    mock_tls.return_value = make_query("example.com", "A")
    query = make_query("example.com", "A")
    resolver_addr = NetworkAddress("1.1.1.1", 853)

    result = DomainResolver.resolve_static(
        mode=DnsProxyMode.DOT,
        message=query,
        resolver=resolver_addr,
        timeout=3,
        hostname="cloudflare-dns.com",
        add_sni=True,
    )

    assert result is not None
    mock_tls.assert_called_once_with(
        query, where="1.1.1.1", port=853, timeout=3, server_hostname="cloudflare-dns.com", verify=True
    )
