from argparse import Namespace, ArgumentParser

from enumerators.DnsProxyMode import DnsProxyMode
from modules.Module import Module
from network.NetworkAddress import NetworkAddress
from modules.dns.DnsProxy import DnsProxy


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
                                help='Mode that the DNS proxy operates in. Default AUTO. If not set to AUTO, still attempts to automatically determine a resolver for the configured mode. To pre-define the used DNS mode and server set this flag and the dns_resolver_host and optionally the dns_resolver_port flags.')

        dns_module.add_argument('--dns_timeout', type=int,
                                default=3,
                                help=f'Connection timeout in seconds. For the {DnsProxyMode.LAST_RESPONSE} mode this timeout will always be reached. Set this timeout and the timeout of calling application accordingly.')

        dns_module.add_argument('--dns_host', type=str,
                                default="localhost",
                                help='Address the proxy server runs on')

        dns_module.add_argument('--dns_port', type=int,
                                default=4433,
                                help='Port the proxy server runs on')

        dns_module.add_argument('--dns_resolver_host', type=str,
                                default=None,
                                help='DNS resolver IP. If set, must correspond to the selected dns_mode.')

        dns_module.add_argument('--dns_resolver_port', type=str,
                                default=None,
                                help='DNS resolver port. If set, must correspond to the selected dns_mode. If unset, port is chosen based on the chosen or determined mode\'s standard port')

        dns_module.add_argument('--dns')


    def extract_parameters(self, args: Namespace):
        server_address = NetworkAddress(args.dns_host, args.dns_port)
        resolver_address = NetworkAddress(args.dns_resolver_host, args.dns_port)
        self.proxy = DnsProxy(server_address, args.dns_timeout, args.dns_mode, resolver_address)

    def start(self):
        self.proxy.start()

    def stop(self):
        self.proxy.continue_processing = False

