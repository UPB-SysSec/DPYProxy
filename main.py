#!/usr/bin/env python3

import argparse
import logging
import sys
import threading
import time
from argparse import ArgumentParser
from enum import Enum
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from enumerators.Modules import Modules
from modules.dns.DnsModule import DnsModule
from modules.Module import Module
from modules.tls.TlsModule import TlsModule

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


class ArgsHelpFormatter(argparse.HelpFormatter):
    def _get_help_string(self, action):
        help_text = action.help or ""
        skip_adding_default = ["dns_compare_ip_ranges"]

        if action.dest in skip_adding_default or action.default in (None, argparse.SUPPRESS, "==SUPPRESS=="):
            return help_text

        def fmt(x):
            if isinstance(x, type):
                return x.__name__
            if isinstance(x, Enum):
                return x.name
            return str(x)

        # Process lists or single items using the new def function
        if isinstance(action.default, list):
            val = ",".join(fmt(i) for i in action.default)
        else:
            val = fmt(action.default)

        # Only append if we actually ended up with a value string
        if val:
            return f"{help_text} (default: {val})"

        return help_text


def validate_args(parser: ArgumentParser, args):
    tls_forward_proxy_host = getattr(args, "tls_forward_proxy_host", None)
    tls_forward_proxy_port = getattr(args, "tls_forward_proxy_port", None)
    if (tls_forward_proxy_host is None) != (tls_forward_proxy_port is None):
        parser.error("Both --tls_forward_proxy_host and --tls_forward_proxy_port must be specified together.")

    # validate dns server arguments, tls_dns_server_port is 53 by default
    tls_dns_server_ip = getattr(args, "tls_dns_server_ip", None)
    tls_dns_server_port = getattr(args, "tls_dns_server_port", None)
    if (tls_dns_server_port is None) != (tls_dns_server_ip is None):
        parser.error("Both --tls_dns_server_ip and --tls_dns_server_port must be specified together.")

    dns_censored_domain = getattr(args, "dns_censored_domain", None)
    dns_compare_ip_ranges = getattr(args, "dns_compare_ip_ranges", None)
    if (dns_compare_ip_ranges is None) != (dns_censored_domain is None):
        parser.error("Both --dns_compare_ip_ranges and --dns_censored_domain must be specified together.")


def extract_activated_modules(parser: ArgumentParser) -> list[Module]:

    def list_of_modules(arg):
        if arg is None or len(arg) == 0:
            return []
        return list(map(lambda x: Modules.__getitem__(x.upper()), arg.split(",")))

    general = parser.add_argument_group("Standard options")

    general.add_argument("-h", "--help", action="help", help="Show this help message and exit")

    general.add_argument("--debug", default=False, action="store_true", help="Turns on debugging")

    general.add_argument(
        "--disabled_modules",
        type=list_of_modules,
        default=[Modules.HTTP],
        help="List of proxy modules to disable. By default, only the HTTP module is disabled."
        " Available choices: " + ",".join([x.name for x in Modules]),
    )

    general.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {get_version()}",
        help="Show program's version",
    )
    # only parse arguments of basic module to determine used modules
    args = parser.parse_known_args()[0]

    # change logging
    if args.debug:
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    else:
        logging.basicConfig(stream=sys.stderr, level=logging.INFO)

    # crate and set enabled modules
    return list(map(lambda x: x.create_module(parser), [x for x in Modules if x not in args.disabled_modules]))


def get_version() -> str:
    try:
        ver = version("dpyproxy")
    except PackageNotFoundError:
        # Looks for pyproject.toml in the current directory
        toml_path = Path("pyproject.toml")

        if toml_path.exists():
            with toml_path.open("rb") as f:
                ver = tomllib.load(f)["project"]["version"]
        else:
            ver = "unknown"
    return ver


def main():
    """
    Starts the proxy with all enabled modules.
    """
    # initialize argumentParser
    parser = argparse.ArgumentParser(
        description="Proxy for circumventing DPI-based censorship.",
        usage="%(prog)s [options]",
        add_help=False,
        formatter_class=ArgsHelpFormatter,
    )

    # parse options of other modules
    for otherModule in Modules:
        otherModule.get_class().register_parameters(parser)

    activated_modules = extract_activated_modules(parser)
    parsed_args = parser.parse_args()
    validate_args(parser, parsed_args)

    for otherModule in activated_modules:
        otherModule.extract_parameters(parsed_args)

    # if tls module and DNS module are running provide dns server to tls module
    dns_module = next((mod for mod in activated_modules if isinstance(mod, DnsModule)), None)
    tls_module = next((mod for mod in activated_modules if isinstance(mod, TlsModule)), None)

    if dns_module and tls_module:
        logging.info("DNS Module and TLS module found. Setting DNS server for TLS Module")
        tls_module.set_dns_server(dns_module.server_address)
        tls_module.extract_parameters(parsed_args)

    # start modules
    for otherModule in activated_modules:
        threading.Thread(target=otherModule.start).start()

    try:
        while True:
            time.sleep(1000)
    except KeyboardInterrupt:
        logging.info("Received Keyboard Interrupt. Cancelling modules and exiting!")
        for otherModule in activated_modules:
            otherModule.stop()
        sys.exit(0)


if __name__ == "__main__":
    main()
