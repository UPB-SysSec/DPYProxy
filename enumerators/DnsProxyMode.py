from enum import Enum


class DnsProxyMode(Enum):
    """
    Possible DNS Modes
    """
    AUTO = "AUTO"
    UDP = "UDP"
    DOT = "DOT"
    DOH = "DOH"
    DOQ = "DOQ"
    TCP = "TCP"
    TCP_FRAG = "TCP_FRAG"
    CHINA = "CHINA"

    def __str__(self):
        return self.name