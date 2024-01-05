from enum import Enum


class ProxyMode(Enum):
    """
    Modes the proxy can operate in
    """
    HTTP = "HTTP"
    HTTPS = "HTTPS",
    SNI = "SNI"
    # TODO: SOCKSv4 = "SOCKSv4
    # TODO: SOCKSv5 = "SOCKSv5

    def __str__(self):
        return self.name