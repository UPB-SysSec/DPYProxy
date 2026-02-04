import logging
from enum import Enum

from enumerators.Port import Port


class DnsProxyMode(Enum):
    """
    Possible DNS Modes
    """
    AUTO = "AUTO"
    UDP = "UDP"
    DOT = "DOT"
    DOH = "DOH"
    DOH3 = "DOH3"
    DOQ = "DOQ"
    TCP = "TCP"
    TCP_FRAG = "TCP_FRAG"
    LAST_RESPONSE = "LAST_RESPONSE"

    def __str__(self):
        return self.name

    def default_port(self) -> int:
        if self==DnsProxyMode.UDP or self==DnsProxyMode.LAST_RESPONSE or self==DnsProxyMode.TCP or self==DnsProxyMode.TCP_FRAG:
            return Port.DNS.value
        elif self==DnsProxyMode.DOT or self==DnsProxyMode.DOQ:
            return Port.DOT.value
        elif self==DnsProxyMode.DOH or self==DnsProxyMode.DOH3:
            return Port.DOH.value
        else:
            logging.error("AUTO mode does not have a default port.")
            return 0
