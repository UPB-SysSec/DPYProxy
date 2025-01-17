from enum import Enum


class DnsMode(Enum):
    """
    Possible DNS Modes
    """
    AUTO = "AUTO"
    DOT = "DOT"
    DOH = "DOH"
    DOQ = "DOQ"

    def __str__(self):
        return self.name