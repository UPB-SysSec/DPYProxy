import socket

from dns.message import Message
from dns.query import tls, tcp, https, udp, HTTPVersion

from enumerators.DnsProxyMode import DnsProxyMode
from exception.DnsException import DnsException
from network.NetworkAddress import NetworkAddress
from network.tcp.WrappedTcpSocket import WrappedTcpSocket


def fix_transaction_id(f):
    """
    Fixes the transaction id for upgraded DNS requests. DoQ specifies and DoH recommends setting the transaction id to 0
    https://www.rfc-editor.org/rfc/rfc9250.html#section-4.2.1
    """
    def _inner(self, message):
        _id = message.id
        # dnspython replaces message.id with 0 in this call
        answer = f(self, message)
        answer.id = _id
        return answer
    return _inner

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
                 dns_mode: DnsProxyMode,
                 timeout: int,
                 tcp_frag_size: int):
        self.udp_resolver = udp_dns_resolver
        self.tcp_resolver = tcp_dns_resolver
        self.tcp_frag_resolver = tcp_frag_dns_resolver
        self.doh_resolver = doh_dns_resolver
        self.doq_resolver = doq_dns_resolver
        self.dot_resolver = dot_dns_resolver
        self.dns_mode = dns_mode
        self.timeout = timeout
        self.tcp_frag_size = tcp_frag_size


    @staticmethod
    def resolve_local(domain: str) -> str:
        """
        Resolves the given domain to an ip address using the system's DNS resolver.
        """
        return socket.gethostbyname(domain)

    @fix_transaction_id
    def resolve_dot(self, message: Message) -> Message:
        """
        Resolves the given domain to an ip address using DNS over TLS on the given DNS resolver.
        :param message: the DNS message to resolve
        :return: One ip address for the domain or None
        """

        return tls(message, where=self.dot_resolver.host, port=self.dot_resolver.port, timeout = self.timeout)

    @fix_transaction_id
    def resolve_doh(self, message: Message) -> Message:
        """
        Resolves the given domain to an ip address using DNS over HTTPS on the given DNS resolver.
        :param message: the DNS message to resolve
        :return: One ip address for the domain or None
        """
        # TODO: check http support through httpx dependency
        return https(message, where=self.doh_resolver.host, port=self.doh_resolver.port, http_version=HTTPVersion.H2, timeout = self.timeout)

    @fix_transaction_id
    def resolve_doq(self, message: Message) -> Message:
        """
        Resolves the given domain to an ip address using DNS over QUIC on the given DNS resolver.
        :param message: the DNS message to resolve
        :return: One ip address for the domain or None
        """
        # TODO: check quic support through aioquic dependency
        return https(message, where=self.doq_resolver.host, port=self.doq_resolver.port, http_version=HTTPVersion.H3, timeout = self.timeout)

    def resolve_udp(self, message: Message) -> Message:
        """
        Resolves the given domain to an ip address using DNS over UDP on the given DNS resolver.
        :param message: the DNS message to resolve
        :return: One ip address for the domain or None
        """

        return udp(message, where=self.udp_resolver.host, port=self.udp_resolver.port, timeout = self.timeout)

    def resolve_tcp(self, message: Message) -> Message:
        """
        Resolves the given domain to an ip address using DNS over TCP on the given DNS resolver.
        :param message: the DNS message to resolve
        :return: One ip address for the domain or None
        """

        return tcp(message, where=self.tcp_resolver.host, port=self.tcp_resolver.port, timeout = self.timeout)

    def resolve_tcp_frag(self, message: Message) -> Message:
        """
        Resolves the given domain to an ip address using DNS over TCP with fragmentation on the given DNS resolver.
        :param message: the DNS message to resolve
        :return: One ip address for the domain or None
        """
        # create fragmenting tcp socket and pass to dnspython
        try:
            _socket = socket.create_connection((self.tcp_frag_resolver.host, self.tcp_frag_resolver.port), timeout = self.timeout)
        except Exception as e:
            raise DnsException(e)

        frag_socket = WrappedTcpSocket(timeout = self.timeout, _socket = _socket, tcp_frag_size=self.tcp_frag_size)
        return tcp(message, where=self.tcp_frag_resolver.host, port=self.tcp_frag_resolver.port, sock=frag_socket, timeout = self.timeout)

    def resolve_china(self, message: Message) -> Message:
        """
        Resolves the given domain to an ip address over UDP but waiting a certain timeout and forwarding the last answer
         received. This circumvents China-specific censorship.
        """

        #TODO
        pass
