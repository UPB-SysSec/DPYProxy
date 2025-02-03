from enum import Enum


class DnsProxyMode(Enum):
    """
    Possible DNS Modes
    """
    AUTO = "AUTO"
    UDP = "UDP"
    DOT = "DOT"
    DOH = "DOH"
    # TODO: difference between DoQ and DoH3?
    DOQ = "DOQ"
    TCP = "TCP"
    TCP_FRAG = "TCP_FRAG"
    LAST_RESPONSE = "LAST_RESPONSE"

    def __str__(self):
        return self.name