import logging
import string
import sys

import argparse

from enumerators.ProxyMode import ProxyMode
from enumerators.TlsVersion import TlsVersion
from network.Proxy import Proxy
from network.NetworkAddress import NetworkAddress


def initialize_parser():
    """
    Registers all arguments for command line parsing.
    :return:
    """

    def list_of_modes(arg):
        return list(map(lambda x: ProxyMode(x), arg.split(",")))

    def record_header_version(arg):
        try:
            return TlsVersion.__getitem__(arg).value
        except:
            if len(arg) == 4 and all(c in string.hexdigits for c in arg):
                return arg
            else:
                logging.error(f"{arg} not a predefined TLS version, not 2 bytes long or contains non-hex characters.")
                exit()

    parser = argparse.ArgumentParser(description='Proxy for circumventing DPI-based censorship.',
                                     usage='%(prog)s [options]', add_help=False)

    # Standard arguments
    general = parser.add_argument_group('Standard options')

    general.add_argument('-h', '--help', action='help',
                         help='Show this help message and exit')

    general.add_argument('--debug', type=bool,
                         default=False,
                         action=argparse.BooleanOptionalAction,
                         help="Turns on debugging")

    general.add_argument('--disabled_modes', type=list_of_modes,
                         choices=ProxyMode,
                         default=[],
                         help='List of proxy modes to ignore. By default, all none are disabled. Hence, all are enabled')

    general.add_argument('--timeout', type=int,
                         default=120,
                         help='Connection timeout in seconds')

    general.add_argument('--host', type=str,
                         default="localhost",
                         help='Address the proxy server runs on')

    general.add_argument('--port', type=int,
                         default=4433,
                         help='Port the proxy server runs on')

    circumventions = parser.add_argument_group('Circumvention options')

    circumventions.add_argument('--version_record_header', type=record_header_version,
                                default=TlsVersion.DEFAULT.value,
                                help=f'Overwrites the TLS version in the TLS record with the given bytes. Pre-defined '
                                     f'values {[x.name for x in TlsVersion]} or 2 byte long values such as 0303 or '
                                     f'FFFF can be provded.', )

    circumventions.add_argument('--record_frag', type=bool,
                                default=True,
                                action=argparse.BooleanOptionalAction,
                                help='Whether to use record fragmentation to forwarded TLS handshake messages')

    circumventions.add_argument('--tcp_frag', type=bool,
                                default=True,
                                action=argparse.BooleanOptionalAction,
                                help='Whether to use TCP fragmentation to forwarded messages.')

    circumventions.add_argument('--frag_size', type=int,
                                default=20,
                                help='Bytes in each TCP/TLS record fragment')

    circumventions.add_argument('--dot_resolver', type=str,
                                default=None,
                                help='DNS server IP for DNS over TLS')

    forward_proxy = parser.add_argument_group('Forward proxy options')

    forward_proxy.add_argument('--forward_proxy_host', type=str,
                               default='localhost',
                               help='Host of the forward proxy if any is present')

    forward_proxy.add_argument('--forward_proxy_port', type=int,
                               default=None,
                               help='Port the forward proxy server runs on')

    forward_proxy.add_argument('--forward_proxy_mode', type=ProxyMode.__getitem__,
                               choices=ProxyMode,
                               default=ProxyMode.HTTPS,
                               help='The proxy type of the forward proxy')

    forward_proxy.add_argument('--forward_proxy_resolve_address', type=bool,
                               default=False,
                               action=argparse.BooleanOptionalAction,
                               help='''Whether to resolve domains before including them in the HTTP CONNECT request to the
                        second proxy''')

    return parser.parse_args()


def main():
    """
    Initializes command line parsing and starts a proxy.
    :return: None
    """
    args = initialize_parser()

    if args.debug:
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    else:
        logging.basicConfig(stream=sys.stderr, level=logging.INFO)

    server_address = NetworkAddress(args.host, args.port)
    forward_proxy = None
    if args.forward_proxy_port is not None:
        forward_proxy = NetworkAddress(args.forward_proxy_host, args.forward_proxy_port)

    if args.forward_proxy_mode in [ProxyMode.HTTP, ProxyMode.SNI] and args.forward_proxy_mode != args.proxy_mode:
        logging.debug("Forward proxy modes HTTP and SNI only usable if proxy mode is HTTP or SNI respectively.")
        exit()

    proxy = Proxy(server_address, args.timeout, args.version_record_header, args.record_frag, args.tcp_frag,
                  args.frag_size, args.dot_resolver, args.disabled_modes, forward_proxy, args.forward_proxy_mode,
                  args.forward_proxy_resolve_address)
    proxy.start()


if __name__ == '__main__':
    main()
