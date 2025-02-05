from enum import Enum


class Port(Enum):
    """
    Default protocol ports
    """
    DNS = 53
    DOT = 853
    DOH = 443