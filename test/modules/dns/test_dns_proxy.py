from unittest.mock import MagicMock, patch

import pytest
from dns.message import make_query

from enumerators.DnsProxyMode import DnsProxyMode
from exception.DnsException import DnsException
from modules.dns.DnsProxy import DnsProxy
from network.NetworkAddress import NetworkAddress


@pytest.fixture
def proxy():
    p = DnsProxy(
        address=NetworkAddress("127.0.0.1", 5533),
        timeout=3,
        proxy_mode=DnsProxyMode.UDP,
        dns_resolver_address=NetworkAddress("8.8.8.8", 53),
        censored_domain="example.com",
        compare_ip_ranges=[],
        block_page_ips=False,
        add_sni=False,
    )
    # mock sockets
    p.udp_server = MagicMock()
    p.tcp_server = MagicMock()
    return p


def test_handle_udp(proxy):
    """
    Test that handle_udp correctly routes incoming UDP queries to resolve_message
    and transmits the resolved response back to the client.
    """
    query = make_query("example.com", "A")
    address = NetworkAddress("127.0.0.1", 12345)

    with patch.object(proxy, "resolve_message") as mock_resolve:
        mock_resolve.return_value = make_query("example.com", "A")
        proxy.handle_udp(query.to_wire(), address)

        mock_resolve.assert_called_once_with(query.to_wire(), address)
        proxy.udp_server.sendto.assert_called_once()


def test_handle_tcp(proxy):
    """
    Test that handle_tcp reads query length prefix, extracts query payload,
    resolves it, and writes length-prefixed response back to the client socket.
    """
    address = NetworkAddress("127.0.0.1", 12345)
    mock_socket = MagicMock()

    query = make_query("example.com", "A")
    wire_data = query.to_wire()

    # Mock length and data
    mock_socket.read.side_effect = [len(wire_data).to_bytes(2, "big"), wire_data]

    with patch.object(proxy, "resolve_message") as mock_resolve:
        mock_resolve.return_value = query
        proxy.handle_tcp(mock_socket, address)

        mock_resolve.assert_called_once_with(request=wire_data, address=address)
        mock_socket.send.assert_called_once()


def test_handle_tcp_exception(proxy):
    """
    Test that handle_tcp handles connection or read errors gracefully without
    triggering resolve_message.
    """
    address = NetworkAddress("127.0.0.1", 12345)
    mock_socket = MagicMock()
    mock_socket.read.side_effect = Exception("Read error")

    with patch.object(proxy, "resolve_message") as mock_resolve:
        proxy.handle_tcp(mock_socket, address)
        mock_resolve.assert_not_called()


def test_generate_domain_resolver_auto(proxy):
    """
    Test that generate_domain_resolver correctly initiates auto-detection mode
    to select the best DNS resolver when AUTO mode is set.
    """
    proxy.proxy_mode = DnsProxyMode.AUTO
    with patch("modules.dns.DnsProxy.DnsModeDeterminator") as mock_det:
        mock_instance = mock_det.return_value
        mock_instance.generate_working_resolver.return_value = iter(["resolver_auto"])
        gen = proxy.generate_domain_resolver()
        assert next(gen) == "resolver_auto"


def test_generate_domain_resolver_mode(proxy):
    """
    Test that generate_domain_resolver initiates auto-detection using mode-specific
    criteria when proxy_mode is set to UDP but resolver host is not provided.
    """
    proxy.proxy_mode = DnsProxyMode.UDP
    proxy.resolver_address.host = None
    with patch("modules.dns.DnsProxy.DnsModeDeterminator") as mock_det:
        mock_instance = mock_det.return_value
        mock_instance.generate_working_resolver.return_value = iter(["resolver_mode"])
        gen = proxy.generate_domain_resolver()
        assert next(gen) == "resolver_mode"


def test_generate_domain_resolver_host_no_port(proxy):
    """
    Test that generate_domain_resolver correctly applies default DNS port 53
    when resolver host is specified without a port number.
    """
    proxy.proxy_mode = DnsProxyMode.UDP
    proxy.resolver_address.host = "8.8.8.8"
    proxy.resolver_address.port = None
    gen = proxy.generate_domain_resolver()
    resolver = next(gen)
    assert resolver.resolver.host == "8.8.8.8"
    assert resolver.resolver.port == 53


def test_generate_domain_resolver_host_and_port(proxy):
    """
    Test that generate_domain_resolver preserves both custom host and port
    on the generated domain resolver instance.
    """
    proxy.proxy_mode = DnsProxyMode.UDP
    proxy.resolver_address.host = "8.8.8.8"
    proxy.resolver_address.port = 1234
    gen = proxy.generate_domain_resolver()
    resolver = next(gen)
    assert resolver.resolver.host == "8.8.8.8"
    assert resolver.resolver.port == 1234


def test_configure_success(proxy):
    """
    Test that configure successfully binds a working domain resolver to the DnsProxy.
    """
    with (
        patch.object(proxy, "generate_domain_resolver") as mock_gen,
        patch("modules.dns.DnsProxy.DomainResolver") as mock_domain_resolver_class,
    ):
        mock_domain_resolver = MagicMock()
        mock_domain_resolver.works.return_value = True
        mock_domain_resolver.dns_mode = DnsProxyMode.UDP
        mock_domain_resolver_class.return_value = mock_domain_resolver

        mock_dns_resolver = MagicMock()
        mock_gen.return_value = iter([mock_dns_resolver])

        proxy.configure()
        assert proxy.domain_resolver == mock_domain_resolver


def test_configure_failure(proxy):
    """
    Test that configure raises a DnsException if no working domain resolver can
    be generated/found.
    """
    with patch.object(proxy, "generate_domain_resolver") as mock_gen:
        mock_gen.return_value = iter([])
        with pytest.raises(DnsException, match="No working circumvention method found"):
            proxy.configure()
