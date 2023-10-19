import logging
import sys

import argparse

from enumerators.ProxyMode import ProxyMode
from network.Proxy import Proxy


def initialize_parser():
    """
    Registers all arguments for command line parsing.
    :return:
    """
    parser = argparse.ArgumentParser(description='Optional app description')

    parser.add_argument_group('Fast settings')
    parser.add_argument('--setting', type=int,
                        default=-1,
                        help='Fast setting for proxy setup.')

    # Standard arguments
    parser.add_argument_group('Standard arguments')

    parser.add_argument('--debug', type=bool,
                        default=False,
                        action=argparse.BooleanOptionalAction,
                        help="Turns on debugging")

    parser.add_argument('--proxy_mode', type=ProxyMode.__getitem__,
                        choices=ProxyMode,
                        default=ProxyMode.ALL,
                        help='Which type of proxy to run')

    parser.add_argument('--timeout', type=int,
                        default=120,
                        help='Connection timeout in seconds')

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

    parser.add_argument('--dot', type=bool,
                        default=False,
                        action=argparse.BooleanOptionalAction,
                        help='Whether to use dot for address resolution')

    parser.add_argument('--dot_resolver', type=str,
                        default='1.1.1.1',
                        help='DNS server ip for DNS over TLS')

    parser.add_argument_group('Forward proxy arguments')

    parser.add_argument('--forward_proxy_address', type=str,
                        default=None,
                        help='Address of the forward proxy if any is present')

    parser.add_argument('--forward_proxy_port', type=int,
                        default=4433,
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

    setting = args.setting
    if setting == 0:
        proxy = Proxy(args.timeout, args.port, True, True, 20, False, args.dot_resolver,
                      ProxyMode.ALL, '127.0.0.1', 4434, ProxyMode.SNI,
                      False)
    elif setting == 1:
        proxy = Proxy(args.timeout, 4434, False, False, args.frag_size, False, args.dot_resolver,
                      ProxyMode.ALL, None, None, ProxyMode.HTTPS,
                      False)
    else:
        proxy = Proxy(args.timeout, args.port, args.record_frag, args.tcp_frag, args.frag_size, args.dot,
                      args.dot_resolver, args.proxy_mode, args.forward_proxy_address, args.forward_proxy_port,
                      args.forward_proxy_mode, args.forward_proxy_resolve_address)
    proxy.start()


if __name__ == '__main__':
    main()
