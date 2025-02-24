from dataclasses import dataclass

from enumerators.DnsProxyMode import DnsProxyMode
from network.NetworkAddress import NetworkAddress


@dataclass
class DnsResolver:
    name: str
    address: NetworkAddress
    mode: DnsProxyMode
    hostname: str

    def __str__(self):
        return f"{self.name}({self.address} - {self.mode})"