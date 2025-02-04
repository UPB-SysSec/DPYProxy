import socket
import time

from dns.exception import Timeout
from dns.message import Message
from dns.query import tls, tcp, https, quic, udp, send_udp, receive_udp, HTTPVersion

from enumerators.DnsProxyMode import DnsProxyMode
from exception.DnsException import DnsException
from network.NetworkAddress import NetworkAddress
from network.tcp.WrappedTcpSocket import WrappedTcpSocket


def fix_transaction_id(f):
    """
    Fixes the transaction id for upgraded DNS requests. DoQ specifies and DoH recommends setting the transaction id to 0
    https://www.rfc-editor.org/rfc/rfc9250.html#section-4.2.1
    """
    def _inner(message, *args, **kwargs):
        _id = message.id
        # dnspython replaces message.id with 0 in this call
        answer = f(message, *args, **kwargs)
        answer.id = _id
        return answer
    return _inner

class DomainResolver:
    """
    Resolves domains to ip addresses. Can use DNS over TLS, DNS over DoQ, DNS over UDP, DNS over TCP, DNS over TCP with
    TCP fragmentation, and a China-specific mode that circumvents.
    Offers static methods and non-static methods for specifiable and non-specifiable DNS resolvers and timeouts respectively.
    """


    def __init__(self, udp_dns_resolver: NetworkAddress,
                 tcp_dns_resolver: NetworkAddress,
                 tcp_frag_dns_resolver: NetworkAddress,
                 doh_dns_resolver: NetworkAddress,
                 doh3_dns_resolver: NetworkAddress,
                 doq_dns_resolver: NetworkAddress,
                 dot_dns_resolver: NetworkAddress,
                 dns_mode: DnsProxyMode,
                 timeout: int,
                 tcp_frag_size: int):
        self.udp_resolver = udp_dns_resolver
        self.tcp_resolver = tcp_dns_resolver
        self.tcp_frag_resolver = tcp_frag_dns_resolver
        self.doh_resolver = doh_dns_resolver
        self.doh3_resolver = doh3_dns_resolver
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
        # TODO: deprecate in favor of resolve_udp with local resolver
        return socket.gethostbyname(domain)

    @staticmethod
    @fix_transaction_id
    def resolve_dot_static(message: Message, resolver: NetworkAddress, timeout: int) -> Message:
        """
        Resolves the given domain to an ip address using DNS over TLS on the given DNS resolver.
        :param message: the DNS message to resolve
        :param resolver: the DNS resolver to use
        :param timeout: the DNS request timeout
        :return: The Dns response by the resolver
        """
        return tls(message, where=resolver.host, port=resolver.port, timeout = timeout)

    @staticmethod
    @fix_transaction_id
    def resolve_doh_static(message: Message, resolver: NetworkAddress, timeout: int) -> Message:
        """
        Resolves the given domain to an ip address using DNS over HTTPS on the given DNS resolver.
        :param message: the DNS message to resolve
        :param resolver: the DNS resolver to use
        :param timeout: the DNS request timeout
        :return: The Dns response by the resolver
        """
        # TODO: check http support through httpx dependency
        return https(message, where=resolver.host, port=resolver.port, http_version=HTTPVersion.H2, timeout = timeout)

    @staticmethod
    @fix_transaction_id
    def resolve_doh3_static(message: Message, resolver: NetworkAddress, timeout: int) -> Message:
        """
        Resolves the given domain to an ip address using DNS over HTTP3 on the given DNS resolver.
        :param message: the DNS message to resolve
        :param resolver: the DNS resolver to use
        :param timeout: the DNS request timeout
        :return: The Dns response by the resolver
        """
        # TODO: check quic support through aioquic dependency
        return https(message, where=resolver.host, port=resolver.port, http_version=HTTPVersion.H3, timeout = timeout)

    @staticmethod
    @fix_transaction_id
    def resolve_doq_static(message: Message, resolver: NetworkAddress, timeout: int) -> Message:
        """
        Resolves the given domain to an ip address using DNS over QUIC on the given DNS resolver.
        :param message: the DNS message to resolve
        :param resolver: the DNS resolver to use
        :param timeout: the DNS request timeout
        :return: The Dns response by the resolver
        """
        # TODO: check quic support through aioquic dependency
        # TODO: currently does not work with adguard: debug
        return quic(message, where=resolver.host, port=resolver.port, timeout = timeout)

    @staticmethod
    def resolve_udp_static(message: Message, resolver: NetworkAddress, timeout: int) -> Message:
        """
        Resolves the given domain to an ip address using DNS over UDP on the given DNS resolver.
        :param message: the DNS message to resolve
        :param resolver: the DNS resolver
        :return: The Dns response by the resolver
        """

        return udp(message, where=resolver.host, port=resolver.port, timeout = timeout)

    @staticmethod
    def resolve_tcp_static(message: Message, resolver: NetworkAddress, timeout: int) -> Message:
        """
        Resolves the given domain to an ip address using DNS over TCP on the given DNS resolver.
        :param message: the DNS message to resolve
        :param resolver: the DNS resolver
        :param timeout: the DNS timeout
        :return: The Dns response by the resolver
        """
        # call fragmentation method without using fragmentation
        return DomainResolver.resolve_tcp_frag_static(message, resolver, timeout, 0)

    @staticmethod
    def resolve_tcp_frag_static(message: Message, resolver: NetworkAddress, timeout: int, frag_size: int) -> Message:
        """
        Resolves the given domain to an ip address using DNS over TCP with fragmentation on the given DNS resolver.
        :param message: the DNS message to resolve
        :param resolver: the DNS resolver to use
        :param timeout: the DNS timeout
        :param frag_size: size of the TCP segments used to fragment the DNS message. If 0 or negative, the message will
        not be fragmented
        :return: The Dns response by the resolver
        """
        # create fragmenting tcp socket and pass to dnspython
        try:
            _socket = socket.create_connection((resolver.host, resolver.port), timeout = timeout)
        except Exception as e:
            raise DnsException(e)

        frag_socket = WrappedTcpSocket(timeout = timeout, _socket = _socket, tcp_frag_size=frag_size)
        return tcp(message, where=resolver.host, sock=frag_socket, timeout = timeout)

    @staticmethod
    def resolve_last_response_static(message: Message, resolver: NetworkAddress, timeout: int) -> Message:
        """
        Resolves the given domain to an ip address over UDP but waiting a certain timeout and forwarding the last answer
        received. This circumvents China-specific censorship.
        :param message: the DNS message to resolve
        :param resolver: the DNS resolver to use
        :param timeout: timeout in seconds, the last message received in this timeout is returned
        :return: the last DNS response message received from the server in the given timeout
        """
        # create udp socket
        _socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _socket.setblocking(False)
        _address = (resolver.host, resolver.port)
        # send message to server
        send_udp(sock = _socket, what = message, destination=_address, expiration=time.time()+timeout)
        last_received = None
        stop_time = time.time() + timeout
        while True:
            try:
                last_received, _ = receive_udp(sock = _socket, destination=_address, expiration=stop_time)
            except Timeout:
                break
        return last_received

    def resolve_dot(self, message: Message) -> Message:
        return DomainResolver.resolve_dot_static(message, resolver=self.dot_resolver, timeout=self.timeout)

    def resolve_doh(self, message: Message) -> Message:
        return DomainResolver.resolve_doh3_static(message, resolver=self.doh_resolver, timeout=self.timeout)

    def resolve_doh3(self, message: Message) -> Message:
        return DomainResolver.resolve_doh3_static(message, resolver=self.doh3_resolver, timeout = self.timeout)

    def resolve_doq(self, message):
        return DomainResolver.resolve_doq_static(message, resolver=self.doq_resolver, timeout=self.timeout)

    def resolve_udp(self, message: Message) -> Message:
        return DomainResolver.resolve_udp_static(message, self.udp_resolver, self.timeout)

    def resolve_tcp(self, message: Message) -> Message:
        return DomainResolver.resolve_tcp_static(message, resolver=self.tcp_frag_resolver, timeout = self.timeout)

    def resolve_tcp_frag(self, message: Message) -> Message:
        return DomainResolver.resolve_tcp_frag_static(message, resolver=self.tcp_frag_resolver, timeout=self.timeout, frag_size=self.tcp_frag_size)

    def resolve_last_response(self, message: Message):
        return DomainResolver.resolve_last_response_static(message, resolver=self.udp_resolver, timeout=self.timeout)