import logging
from argparse import BooleanOptionalAction, Namespace, ArgumentParser

from enumerators.DnsMode import DnsMode
from enumerators.ProxyMode import ProxyMode
from modules.Module import Module
from network.NetworkAddress import NetworkAddress
from network.Proxy import Proxy


class DnsModule(Module):
    """
    Implements circumvention methods for DNS censorship.
    """

    def __init__(self, parser: ArgumentParser):
        super().__init__(parser)
        self.proxy: Proxy | None = None


    def register_parameters(self):
        dns_module = self.parser.add_argument_group('DNS Module')

        dns_module.add_argument('--dns_disabled_modes', type=DnsMode,
                             default=DnsMode.AUTO,
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

        dns_module.add_argument('--dns_forward_proxy_host', type=str,
                                default='localhost',
                                help='Host of the forward proxy if any is present')

        dns_module.add_argument('--dns_forward_proxy_port', type=int,
                                default=None,
                                help='Port the forward proxy server runs on')

        dns_module.add_argument('--dns_forward_proxy_resolve_address', type=bool,
                                default=False,
                                action=BooleanOptionalAction,
                                help='''Whether to resolve domains before including them in the HTTP CONNECT request to the
                                        second proxy''')

        dns_module.add_argument('--dns_dot_resolver', type=str,
                                default=None,
                                help='DNS server IP for DNS over TLS')

        dns_module.add_argument('--dns_doh_resolver', type=str,
                                default=None,
                                help='DNS server IP for DNS over HTTPS')

        dns_module.add_argument('--dns_doq_resolver', type=str,
                                default=None,
                                help='DNS server IP for DNS over QUIC')


    def extract_parameters(self, args: Namespace):
        server_address = NetworkAddress(args.dns_host, args.dns_port)
        forward_proxy = None
        if args.dns_forward_proxy_port is not None:
            forward_proxy = NetworkAddress(args.dns_forward_proxy_host, args.dns_forward_proxy_port)

        self.proxy = Proxy(server_address, args.dns_timeout, False, False, 0,
                      args.dns_dot_resolver, [ProxyMode.HTTP, ProxyMode.HTTPS, ProxyMode.SNI,
                      ProxyMode.SOCKSv4, ProxyMode.SOCKSv4a, ProxyMode.SOCKSv5], forward_proxy, ProxyMode.DNS,
                      args.forward_proxy_resolve_address)

    def start(self):
        self.proxy.start()

    def stop(self):
        # TODO: make Proxy and Forwarder cancellable
        pass

