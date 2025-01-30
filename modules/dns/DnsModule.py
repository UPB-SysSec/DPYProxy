from argparse import Namespace, ArgumentParser

from enumerators.DnsProxyMode import DnsProxyMode
from enumerators.TcpProxyMode import TcpProxyMode
from modules.Module import Module
from network.NetworkAddress import NetworkAddress
from network.tcp.TcpProxy import TcpProxy


class DnsModule(Module):
    """
    Implements circumvention methods for DNS censorship.
    """

    def __init__(self, parser: ArgumentParser):
        super().__init__(parser)
        self.proxy: TcpProxy | None = None


    def register_parameters(self):
        dns_module = self.parser.add_argument_group('DNS Module')

        dns_module.add_argument('--dns_mode', type=DnsProxyMode,
                                default=DnsProxyMode.AUTO,
                                help='Mode that the DNS proxy operates in. Default AUTO.')

        dns_module.add_argument('--dns_timeout', type=int,
                                default=120,
                                help='Connection timeout in seconds')

        dns_module.add_argument('--dns_host', type=str,
                                default="localhost",
                                help='Address the proxy server runs on')

        dns_module.add_argument('--dns_port', type=int,
                                default=4433,
                                help='Port the proxy server runs on')


        dns_module.add_argument('--dns_dot_resolver', type=str,
                                default=None,
                                help='DNS server IP for DNS over TLS. If empty, the proxy automatically determines a working DoT resolver.')

        dns_module.add_argument('--dns_doh_resolver', type=str,
                                default=None,
                                help='DNS server IP for DNS over HTTPS. If empty, the proxy automatically determines a working DoH resolver')

        dns_module.add_argument('--dns_doq_resolver', type=str,
                                default=None,
                                help='DNS server IP for DNS over QUIC. If empty, the proxy automatically determines a working DoQ resolver')


    def extract_parameters(self, args: Namespace):
        server_address = NetworkAddress(args.dns_host, args.dns_port)
        forward_proxy = None
        if args.dns_forward_proxy_port is not None:
            forward_proxy = NetworkAddress(args.dns_forward_proxy_host, args.dns_forward_proxy_port)

        self.proxy = TcpProxy(server_address, args.dns_timeout, False, False, 0,
                              args.dns_dot_resolver, [TcpProxyMode.HTTP, TcpProxyMode.HTTPS, TcpProxyMode.SNI,
                                                      TcpProxyMode.SOCKSv4, TcpProxyMode.SOCKSv4a, TcpProxyMode.SOCKSv5], forward_proxy, TcpProxyMode.DNS,
                              args.forward_proxy_resolve_address)

    def start(self):
        self.proxy.start()

    def stop(self):
        # TODO: make Proxy and Forwarder cancellable
        pass

