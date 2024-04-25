import logging
import sys

import argparse

from enumerators.NetworkType import NetworkType
from enumerators.ProxyMode import ProxyMode
from network.Proxy import Proxy
from network.NetworkAddress import NetworkAddress


def initialize_parser():
    """
    Registers all arguments for command line parsing.
    :return:
    """

    def list_of_modes(arg):
        return list(map(lambda x: ProxyMode(x), arg.split(",")))

    parser = argparse.ArgumentParser(description='Optional app description')

    # Standard arguments
    parser.add_argument_group('Standard arguments')

    parser.add_argument('--debug', type=bool,
                        default=False,
                        action=argparse.BooleanOptionalAction,
                        help="Turns on debugging")

    parser.add_argument('--disabled_modes', type=list_of_modes,
                        choices=ProxyMode,
                        default=[],
                        help='List of proxy modes to ignore. By default, none are disabled. Hence, all are enabled')

    parser.add_argument('--timeout', type=int,
                        default=120,
                        help='Connection timeout in seconds')

    parser.add_argument('--host', type=str,
                        default="localhost",
                        help='Address the proxy server runs on')

    parser.add_argument('--port', type=int,
                        default=4433,
                        help='Port the proxy server runs on')

    parser.add_argument('--record_frag', type=bool,
                        default=True,
                        action=argparse.BooleanOptionalAction,
                        help='Whether to use record fragmentation to forwarded tls handshake messages')

    parser.add_argument('--tcp_frag', type=bool,
                        default=True,
                        action=argparse.BooleanOptionalAction,
                        help='Whether to use tcp fragmentation to forwarded messages.')

    parser.add_argument('--frag_size', type=int,
                        default=20,
                        help='Bytes in each tpc/ tls record fragment')

    parser.add_argument('--dot_resolver', type=str,
                        default=None,
                        help='DNS server ip for DNS over TLS')

    parser.add_argument('--force_ipv6', type=bool,
                        default=False,
                        help='Force IPv6 when connecting to other servers')

    parser.add_argument('--force_ipv4', type=bool,
                        default=False,
                        help='Force IPv4 when connecting to other servers')

    parser.add_argument_group('Forward proxy arguments')

    parser.add_argument('--forward_proxy_host', type=str,
                        default='localhost',
                        help='Host of the forward proxy if any is present')

    parser.add_argument('--forward_proxy_port', type=int,
                        default=None,
                        help='Port the forward proxy server runs on')

    parser.add_argument('--forward_proxy_mode', type=ProxyMode.__getitem__,
                        choices=ProxyMode,
                        default=ProxyMode.HTTPS,
                        help='The proxy type of the forward proxy')

    parser.add_argument('--forward_proxy_resolve_address', type=bool,
                        default=False,
                        action=argparse.BooleanOptionalAction,
                        help='Whether to resolve domain before including it in eventual HTTP CONNECT request to second '
                             'proxy')

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

    if args.force_ipv4 and args.force_ipv6:
        logging.debug("Cannot force both ipv4 and ipv6.")
        exit()
    elif args.force_ipv4:
        domain_resolution = NetworkType.IPV4
    elif args.force_ipv6:
        domain_resolution = NetworkType.IPV6
    else:
        domain_resolution = NetworkType.DUAL_STACK

    if args.forward_proxy_mode in [ProxyMode.HTTP, ProxyMode.SNI] and args.forward_proxy_mode != args.proxy_mode:
        logging.debug("Forward proxy modes HTTP and SNI only usable if proxy mode is HTTP or SNI respectively.")
        exit()

    proxy = Proxy(server_address, args.timeout, args.record_frag, args.tcp_frag, args.frag_size,
                  args.dot_resolver, domain_resolution, args.disabled_modes, forward_proxy,
                  args.forward_proxy_mode, args.forward_proxy_resolve_address)
    proxy.start()


if __name__ == '__main__':
    main()
