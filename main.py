import argparse
import logging
import sys
import time
from argparse import ArgumentParser

from enumerators.Modules import Modules
from modules.Module import Module


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
                         default=[],
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


if __name__ == '__main__':
    main()
