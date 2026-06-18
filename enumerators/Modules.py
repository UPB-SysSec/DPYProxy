from argparse import ArgumentParser
from enum import Enum

from modules.dns.DnsModule import DnsModule
from modules.http.HttpModule import HttpModule
from modules.tls.TlsModule import TlsModule


class Modules(Enum):
    """
    All optional modules the proxy supports
    """

    TLS = "TLS"
    DNS = "DNS"
    HTTP = "HTTP"

    def create_module(self, parser: ArgumentParser):
        """
        Created a new Module object based the enumerator type.
        """
        if self == Modules.TLS:
            return TlsModule(parser)
        elif self == Modules.DNS:
            return DnsModule(parser)
        elif self == Modules.HTTP:
            return HttpModule(parser)

    def get_class(self):
        """
        Returns the class of the module.
        """
        if self == Modules.TLS:
            return TlsModule
        elif self == Modules.DNS:
            return DnsModule
        elif self == Modules.HTTP:
            return HttpModule
