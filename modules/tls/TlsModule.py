import logging
import string
from argparse import BooleanOptionalAction, Namespace, ArgumentParser

from enumerators.TcpProxyMode import TcpProxyMode
from enumerators.TlsVersion import TlsVersion
from modules.Module import Module
from modules.tls.TcpProxy import TcpProxy
from network.NetworkAddress import NetworkAddress


class TlsModule(Module):
    """
    Implements circumvention methods for the TLS SNI censorship. Currently, implements options for a general TCP socket
    as TLS is the only TCP-based protocol we support. In future version, those should be abstracted into their own
    module.
    """

    def __init__(self, parser: ArgumentParser):
        super().__init__(parser)
        self.proxy: TcpProxy | None = None
        self.dns_server = None

    @staticmethod
    def register_parameters(parser: ArgumentParser):

        def list_of_modes(arg):
            return list(map(lambda x: TcpProxyMode(x), arg.split(",")))

        def record_header_version(arg):
            try:
                return TlsVersion.__getitem__(arg).value
            except:
                if len(arg) == 4 and all(c in string.hexdigits for c in arg):
                    return arg
                else:
                    logging.error(f"{arg} not a predefined TLS version, not 2 bytes long or contains non-hex characters.")
                    exit()

        tls_module = parser.add_argument_group('TLS Module')

        tls_module.add_argument('--tls_disabled_modes', type=list_of_modes,
                                choices=TcpProxyMode,
                                default=[],
                                help='List of proxy modes to ignore. By default, all none are disabled. Hence, all are enabled')

        tls_module.add_argument('--tls_timeout', type=int,
                             default=10,
                             help='Connection timeout in seconds')

        tls_module.add_argument('--tls_host', type=str,
                             default="localhost",
                             help='Address the proxy server runs on')

        tls_module.add_argument('--tls_port', type=int,
                             default=4433,
                             help='Port the proxy server runs on')

        tls_module.add_argument('--tls_record_version', type=record_header_version,
                                    default=TlsVersion.DEFAULT.name,
                                    help=f'Overwrites the TLS version in the TLS record with the given bytes. Pre-defined '
                                         f'values {[x.name for x in TlsVersion]} or 2 byte long values such as 0303 or '
                                         f'FFFF can be provided.', )


        tls_module.add_argument('--tls_record_frag', type=bool,
                                    default=True,
                                    action=BooleanOptionalAction,
                                    help='Whether to use record fragmentation to forwarded TLS handshake messages')

        tls_module.add_argument('--tls_tcp_frag', type=bool,
                                    default=True,
                                    action=BooleanOptionalAction,
                                    help='Whether to use TCP fragmentation to forwarded messages.')

        tls_module.add_argument('--tls_frag_size', type=int,
                                    default=20,
                                    help='Bytes in each TCP/TLS record fragment')

        tls_module.add_argument('--tls_dns_server_ip', type=str,
                                    default=None,
                                    help='DNS server IP for all DNS queries of the TLS module. If not given, the DNS server started by the DNS module us used. If DNS module is not used, the OS default DNS server is used.')

        tls_module.add_argument('--tls_dns_server_port', type=int,
                                    default=53,
                                    help='DNS server port for all DNS queries. Only set if a DNS server IP is given. If not given, the default port 53 is used.')

        tls_module.add_argument('--tls_forward_proxy_host', type=str,
                                   default='localhost',
                                   help='Host of the forward proxy if any is present')

        tls_module.add_argument('--tls_forward_proxy_port', type=int,
                                   default=None,
                                   help='Port the forward proxy server runs on')

        tls_module.add_argument('--tls_forward_proxy_mode', type=TcpProxyMode.__getitem__,
                                choices=TcpProxyMode,
                                default=TcpProxyMode.HTTPS,
                                help='The proxy type of the forward proxy')

        tls_module.add_argument('--tls_forward_proxy_resolve_address', type=bool,
                                   default=False,
                                   action=BooleanOptionalAction,
                                   help='''Whether to resolve domains before including them in the HTTP CONNECT request to the
                                second proxy''')


    def extract_parameters(self, args: Namespace):
        server_address = NetworkAddress(args.tls_host, args.tls_port)
        forward_proxy = None
        if args.tls_forward_proxy_port is not None:
            forward_proxy = NetworkAddress(args.tls_forward_proxy_host, args.tls_forward_proxy_port)

        if args.tls_dns_server_ip is not None and self.dns_server is None:
            self.dns_server = NetworkAddress(args.tls_dns_server_ip, args.tls_dns_server_port)

        if args.tls_forward_proxy_mode in [TcpProxyMode.HTTP, TcpProxyMode.SNI] and args.tls_forward_proxy_mode != args.proxy_mode:
            logging.debug("Forward proxy modes HTTP and SNI only usable if proxy mode is HTTP or SNI respectively.")
            exit()

        self.proxy = TcpProxy(server_address, args.tls_timeout, args.tls_record_version, args.tls_record_frag, args.tls_tcp_frag, args.tls_frag_size,
                              self.dns_server, args.tls_disabled_modes, forward_proxy, args.tls_forward_proxy_mode,
                              args.tls_forward_proxy_resolve_address)

    def start(self):
        self.proxy.start()

    def stop(self):
        self.proxy.continue_processing = False
        logging.info("Waiting for proxy to stop")

    def set_dns_server(self, dns_server: NetworkAddress):
        """
        Sets the DNS server for the TLS module.
        :param dns_server: NetworkAddress of the DNS server to use.
        """
        if not self.dns_server:
            self.dns_server = NetworkAddress("127.0.0.1" if dns_server.host == "0.0.0.0" else dns_server.host, dns_server.port)
        else:
            logging.warning("DNS server manually overwritten in TLS module. Not setting address of DNS module server.")

