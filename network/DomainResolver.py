import socket

import dns
from dns.message import Message

from enumerators.DnsProxyMode import DnsProxyMode
from network.NetworkAddress import NetworkAddress


class DomainResolver:
    """
    Resolves domains to ip addresses. Can use DNS over TLS, DNS over DoQ, DNS over UDP, DNS over TCP, DNS over TCP with
    TCP fragmentation, and a China-specific mode that circumvents .
    """
    # TODO: DOH / DOQ for DNS mode

    def __init__(self, udp_dns_resolver: NetworkAddress,
                 tcp_dns_resolver: NetworkAddress,
                 tcp_frag_dns_resolver: NetworkAddress,
                 doh_dns_resolver: NetworkAddress,
                 doq_dns_resolver: NetworkAddress,
                 dot_dns_resolver: NetworkAddress,
                 dns_mode: DnsProxyMode):
        self.udp_resolver = udp_dns_resolver
        self.tcp_resolver = tcp_dns_resolver
        self.tcp_frag_resolver = tcp_frag_dns_resolver
        self.doh_resolver = doh_dns_resolver
        self.doq_resolver = doq_dns_resolver
        self.dot_resolver = dot_dns_resolver
        self.dns_mode = dns_mode


    @staticmethod
    def resolve_local(domain: str) -> str:
        """
        Resolves the given domain to an ip address using the system's DNS resolver.
        """
        return socket.gethostbyname(domain)

    def resolve_dot(self, message: Message) -> Message:
        """
        Resolves the given domain to an ip address using DNS over TLS on the given DNS resolver.
        :param message: the DNS message to resolve
        :return: One ip address for the domain or None
        """

        return dns.query.tls(message, where=self.dot_resolver.host, port=self.dot_resolver.port)

    def resolve_doh(self, message: Message) -> Message:
        """
        Resolves the given domain to an ip address using DNS over HTTPS on the given DNS resolver.
        :param message: the DNS message to resolve
        :return: One ip address for the domain or None
        """

        return dns.query.https(message, where=self.doh_resolver.host, port=self.doh_resolver.port)

    def resolve_udp(self, message: Message) -> Message:
        """
        Resolves the given domain to an ip address using DNS over UDP on the given DNS resolver.
        :param message: the DNS message to resolve
        :return: One ip address for the domain or None
        """

        return dns.query.udp(message, where=self.udp_resolver.host, port=self.udp_resolver.port)

    def resolve_tcp(self, message: Message) -> Message:
        """
        Resolves the given domain to an ip address using DNS over TCP on the given DNS resolver.
        :param message: the DNS message to resolve
        :return: One ip address for the domain or None
        """

        return dns.query.tcp(message, where=self.tcp_resolver.host, port=self.tcp_resolver.port)

    def resolve_doq(self, message: Message) -> Message:
        """
        Resolves the given domain to an ip address using DNS over QUIC on the given DNS resolver.
        :param message: the DNS message to resolve
        :return: One ip address for the domain or None
        """
        # TODO
        # return dns.query.quic(message, where=self.doq_resolver.host, port=self.doq_resolver.port)

    def resolve_tcp_frag(self, message: Message) -> Message:
        """
        Resolves the given domain to an ip address using DNS over TCP with fragmentation on the given DNS resolver.
        :param message: the DNS message to resolve
        :return: One ip address for the domain or None
        """
        # TODO
        # return dns.query.tcp_frag(message, where=self.tcp_frag_resolver.host, port=self.tcp_frag_resolver.port)

    def resolve_china(self, message: Message) -> Message:
        """
        Resolves the given domain to an ip address over UDP but waiting a certain timeout and forwarding the last answer
         received. This circumvents China-specific censorship.
        """

        #TODO
        pass