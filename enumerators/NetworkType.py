from enum import Enum


class NetworkType(Enum):
    """
    Modes the proxy can operate in
    """
    IPV4 = "IPv4"
    IPV6 = "IPv6",
    DUAL_STACK = "IPv4+IPv6"

    def __str__(self):
        return self.name
