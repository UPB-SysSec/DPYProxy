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
                                default="www.google.dj",
                                help='A domain name censored in your location. Used to determine working circumventions methods. Specify together with --dns_censored_domain_ip')

        dns_module.add_argument('--dns_compare_ip_ranges', type=str,
                                default='8.8.4.0/24,8.8.8.0/24,8.34.208.0/20,8.35.192.0/20,23.236.48.0/20,23.251.128.0/19,34.0.0.0/15,34.2.0.0/16,34.3.0.0/23,34.3.3.0/24,34.3.4.0/24,34.3.8.0/21,34.3.16.0/20,34.3.32.0/19,34.3.64.0/18,34.4.0.0/14,34.8.0.0/13,34.16.0.0/12,34.32.0.0/11,34.64.0.0/10,34.128.0.0/10,35.184.0.0/13,35.192.0.0/14,35.196.0.0/15,35.198.0.0/16,35.199.0.0/17,35.199.128.0/18,35.200.0.0/13,35.208.0.0/12,35.224.0.0/12,35.240.0.0/13,57.140.192.0/18,64.15.112.0/20,64.233.160.0/19,66.22.228.0/23,66.102.0.0/20,66.249.64.0/19,70.32.128.0/19,72.14.192.0/18,74.114.24.0/21,74.125.0.0/16,104.154.0.0/15,104.196.0.0/14,104.237.160.0/19,107.167.160.0/19,107.178.192.0/18,108.59.80.0/20,108.170.192.0/18,108.177.0.0/17,130.211.0.0/16,136.22.160.0/20,136.22.176.0/21,136.22.184.0/23,136.22.186.0/24,136.124.0.0/15,142.250.0.0/15,146.148.0.0/17,152.65.208.0/22,152.65.214.0/23,152.65.218.0/23,152.65.222.0/23,152.65.224.0/19,162.120.128.0/17,162.216.148.0/22,162.222.176.0/21,172.110.32.0/21,172.217.0.0/16,172.253.0.0/16,173.194.0.0/16,173.255.112.0/20,192.104.160.0/23,192.158.28.0/22,192.178.0.0/15,193.186.4.0/24,199.36.154.0/23,199.36.156.0/24,199.192.112.0/22,199.223.232.0/21,207.223.160.0/20,208.65.152.0/22,208.68.108.0/22,208.81.188.0/22,208.117.224.0/19,209.85.128.0/17,216.58.192.0/19,216.73.80.0/20,216.239.32.0/19,216.252.220.0/22',
                                help='A list of IP ranges the resolved IP of the censored domain lies in. The censored domain is specifiable in --dns_censored_domain.')

        dns_module.add_argument('--dns_block_page_ips', type=bool,
                                default=False,
                                help='Whether the given IP ranges to compare are block page IPs or not. Default is False.')

        dns_module.add_argument('--dns_add_sni', type=bool,
                                default=True,
                                help='Whether or not to include the SNI for encrypted DNS modes. Defaults to True.')

        dns_module.add_argument('--dns_skip_working_file', type=bool,
                                default=False,
                                help='Whether taking the stored working resolver from a file should be skipped. Defaults to False.')


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
                              add_sni=args.dns_add_sni,
                              skip_working_file=args.dns_skip_working_file)

    def start(self):
        self.proxy.start()

    def stop(self):
        self.proxy.continue_processing = False
