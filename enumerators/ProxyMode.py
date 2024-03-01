from enum import Enum


class ProxyMode(Enum):
    """
    Modes the proxy can operate in
    """
    HTTP = "HTTP"
    HTTPS = "HTTPS",
    SNI = "SNI"
    SOCKSv4 = "SOCKSv4"
    SOCKSv4a = "SOCKSv4a"
    SOCKSv5 = "SOCKSv5"

    def __str__(self):
        return self.name