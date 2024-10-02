from enum import Enum


class TlsVersion(Enum):
    """
    Modes the proxy can operate in
    """
    DEFAULT = "XXXX"
    TLS10 = "0301",
    TLS11 = "0302"
    TLS12 = "0303"
    TLS13_DRAFT_28 = "7F1C"
    TLS13 = "0304"
    SSL3 = "0300"
    SSL2 = "0302"
    INVALID_SMALLER = "0000"
    INVALID_BIGGER = "2020"

    def __str__(self):
        return f'{self.name}: {self.value}'
