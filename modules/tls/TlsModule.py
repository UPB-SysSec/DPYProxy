import logging
import threading
from argparse import BooleanOptionalAction, Namespace, ArgumentParser

from enumerators.TcpProxyMode import TcpProxyMode
from modules.Module import Module
from network.NetworkAddress import NetworkAddress
from network.tcp.TcpProxy import TcpProxy


class TlsModule(Module):
    """
    Implements circumvention methods for the TLS SNI censorship. Currently, implements options for a general TCP socket
    as TLS is the only TCP-based protocol we support. In future version, those should be abstracted into their own
    module.
    """

    def __init__(self, parser: ArgumentParser):
        super().__init__(parser)
        self.proxy: TcpProxy | None = None


    def register_parameters(self):

        def list_of_modes(arg):
            return list(map(lambda x: TcpProxyMode(x), arg.split(",")))

        tls_module = self.parser.add_argument_group('TLS Module')

        tls_module.add_argument('--tls_disabled_modes', type=list_of_modes,
                                choices=TcpProxyMode,
                                default=[],
                                help='List of proxy modes to ignore. By default, all none are disabled. Hence, all are enabled')

        tls_module.add_argument('--tls_timeout', type=int,
                             default=120,
                             help='Connection timeout in seconds')

        tls_module.add_argument('--tls_host', type=str,
                             default="localhost",
                             help='Address the proxy server runs on')

        tls_module.add_argument('--tls_port', type=int,
                             default=4433,
                             help='Port the proxy server runs on')


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

        tls_module.add_argument('--tls_dot_resolver', type=str,
                                    default=None,
                                    help='DNS server IP for DNS over TLS')

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

        if args.tls_forward_proxy_mode in [TcpProxyMode.HTTP, TcpProxyMode.SNI] and args.tls_forward_proxy_mode != args.proxy_mode:
            logging.debug("Forward proxy modes HTTP and SNI only usable if proxy mode is HTTP or SNI respectively.")
            exit()

        self.proxy = TcpProxy(server_address, args.tls_timeout, args.tls_record_frag, args.tls_tcp_frag, args.tls_frag_size,
                              args.tls_dot_resolver, args.tls_disabled_modes, forward_proxy, args.tls_forward_proxy_mode,
                              args.tls_forward_proxy_resolve_address)

    def start(self):
        threading.Thread(target=self.proxy.start()).start()

    def stop(self):
        self.proxy.continue_processing = False
        logging.info("Waiting for proxy to stop")

