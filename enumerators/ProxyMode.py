from enum import Enum


class ProxyMode(Enum):
    """
    Modes the proxy can operate in
    """
    ALL = 0,
    HTTP = 1
    HTTPS = 2,
    SNI = 3
    # TODO: SOCKSv4 = 4
    # TODO: SOCKSv5 = 5

    def __str__(self):
        return self.name
