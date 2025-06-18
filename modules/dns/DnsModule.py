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
        self.server_address: NetworkAddress | None = None

    @staticmethod
    def register_parameters(parser: ArgumentParser):
        dns_module = parser.add_argument_group('DNS Module')

        dns_module.add_argument('--dns_mode', type=DnsProxyMode,
                                default=DnsProxyMode.AUTO,
                                help='Mode that the DNS proxy operates in. Default AUTO. If not set to AUTO, still attempts to automatically determine a resolver for the configured mode. To pre-define the used DNS mode and server set this flag and the dns_resolver_host and optionally the dns_resolver_port flags.')

        dns_module.add_argument('--dns_timeout', type=int,
                                default=3,
                                help=f'Connection timeout in seconds. For the {DnsProxyMode.LAST_RESPONSE} mode this timeout will always be reached. Set this timeout and the timeout of calling application accordingly.')

        dns_module.add_argument('--dns_host', type=str,
                                default="127.0.0.1",
                                help='Address the proxy server runs on')

        dns_module.add_argument('--dns_port', type=int,
                                default=5533,
                                help='Port the proxy server runs on')

        dns_module.add_argument('--dns_resolver_host', type=str,
                                default=None,
                                help='DNS resolver IP. If set, must correspond to the selected dns_mode.')

        dns_module.add_argument('--dns_resolver_port', type=str,
                                default=None,
                                help='DNS resolver port. If set, must correspond to the selected dns_mode. If unset, port is chosen based on the chosen or determined mode\'s standard port')

        dns_module.add_argument('--dns_censored_domain', type=str,
                                default="wikipedia.org",
                                # TODO: add .txt document with example values for varying countries
                                help='A domain name censored in your location. Used to determine working circumventions methods. Specify together with --dns_censored_domain_ip')

        dns_module.add_argument('--dns_compare_ip_ranges', type=str,
                                default='185.15.56.0/22,91.198.174.0/24,195.200.68.0/24,193.46.90.0/24,198.35.26.0/23,208.80.152.0/22,103.102.166.0/24',
                                help='A list of IP ranges the resolved IP of the censored domain lies in. The censored domain is specifiable in --dns_censored_domain.')

        dns_module.add_argument('--dns_block_page_ips', type=bool,
                                default=False,
                                help='Whether the given IP ranges to compare are block page IPs or not. Default is False.')

        dns_module.add_argument('--dns_add_sni', type=str,
                                default=True,
                                help='Whether or not to include the SNI for encrypted DNS modes. Defaults to True.')

    def extract_parameters(self, args: Namespace):
        self.server_address = NetworkAddress(args.dns_host, args.dns_port)
        resolver_address = NetworkAddress(args.dns_resolver_host, args.dns_port)

        self.proxy = DnsProxy(proxy_mode=args.dns_mode,
                              address=self.server_address,
                              timeout=args.dns_timeout,
                              dns_resolver_address=resolver_address,
                              censored_domain=args.dns_censored_domain,
                              compare_ip_ranges=[x for x in args.dns_compare_ip_ranges.split(",")],
                              block_page_ips=args.dns_block_page_ips,
                              add_sni=args.dns_add_sni)

    def start(self):
        self.proxy.start()

    def stop(self):
        self.proxy.continue_processing = False
