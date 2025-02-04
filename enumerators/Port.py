from enum import Enum


class Port(Enum):
    """
    Default protocol ports
    """
    DNS = 53
    DOT = 853
    DOH = 443
    DOH3 = 443
    DOQ = 443