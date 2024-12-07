import logging
import sys

import argparse
import time
from argparse import ArgumentParser

from enumerators.Modules import Modules
from enumerators.ProxyMode import ProxyMode
from modules.Module import Module
from modules.base.BaseModule import BaseModule
from network.Proxy import Proxy
from network.NetworkAddress import NetworkAddress


def initialize_parser():
    """
    Registers all arguments for command line parsing.
    :return:
    """





    general.add_argument('--disabled_modes', type= list_of_modes,
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

def extract_activated_modules(parser: ArgumentParser) -> list[Module]:

    def list_of_modules(arg):
        return list(map(lambda x: Modules(x), arg.split(",")))

    general = parser.add_argument_group('Standard options')

    general.add_argument('-h', '--help', action='help',
                         help='Show this help message and exit')

    general.add_argument('--debug', type=bool,
                         default=False,
                         action=argparse.BooleanOptionalAction,
                         help="Turns on debugging")

    general.add_argument('--disabled_modules', type=list_of_modules,
                         choices=Modules,
                         default=[Modules.DNS, Modules.TLS],
                         help='List of proxy modules to disable. By default, all none are disabled. Hence, all are enabled')

    # only parse arguments of basic module to determine used modules
    args = parser.parse_known_args()[0]

    # change logging
    if args.debug:
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    else:
        logging.basicConfig(stream=sys.stderr, level=logging.INFO)

    # crate and set enabled modules
    return list(map(lambda x: x.create_module(parser),
                               [x for x in Modules if x not in args.disabled_modules]))

def main():
    """
    Starts the proxy with all enabled modules.
    """
    # initialize argumentParser
    parser = argparse.ArgumentParser(description='Proxy for circumventing DPI-based censorship.',
                                     usage='%(prog)s [options]', add_help=False)

    activated_modules = extract_activated_modules(parser)

    # parse options of other modules
    for otherModule in activated_modules:
        otherModule.register_parameters()

    # TODO: detect when unknown arguments are of module that was not added, or at least tell the possibility
    parsed_args = parser.parse_args()

    for otherModule in activated_modules:
        otherModule.extract_parameters(parsed_args)

    # start modules
    for otherModule in activated_modules:
        otherModule.start()

    # TODO: remove busy sleeping
    try:
        while True:
            time.sleep(1000)
    except KeyboardInterrupt:
        logging.INFO("Received Keyboard Interrupt. Cancelling modules and exiting!")
        for otherModule in activated_modules:
            otherModule.stop()
        sys.exit(0)


def _main():
    """
    Initializes command line parsing and starts a proxy.
    :return: None
    """

    proxy.start()


if __name__ == '__main__':
    main()
