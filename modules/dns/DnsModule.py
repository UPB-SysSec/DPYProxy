from argparse import Namespace, ArgumentParser

from enumerators.DnsProxyMode import DnsProxyMode
from enumerators.TcpProxyMode import TcpProxyMode
from modules.Module import Module
from network.NetworkAddress import NetworkAddress
from network.tcp.TcpProxy import TcpProxy
from network.udp.DnsProxy import DnsProxy


class DnsModule(Module):
    """
    Implements circumvention methods for DNS censorship.
    """

    def __init__(self, parser: ArgumentParser):
        super().__init__(parser)
        self.proxy: DnsProxy | None = None


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
        self.proxy = DnsProxy(server_address, args.dns_timeout, args.dns_mode)

    def start(self):
        self.proxy.start()

    def stop(self):
        # TODO: make Proxy and Forwarder cancellable
        pass

