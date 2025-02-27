import socket
import ssl
import time

import dns
import httpx
from dns.exception import Timeout
from dns.message import Message
from dns.query import tls, tcp, https, quic, udp, send_udp, receive_udp, HTTPVersion, _http3, _maybe_get_resolver, \
    _destination_and_source, _HTTPTransport, BadResponse, _compute_times, _remaining, _check_status

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

    DNS_TCP_FRAG_SIZE = 20
    THRESHOLD_CONFIRM_WORKING = 3
    TRIES_CONFIRM_WORKING = 5

    def __init__(self,
                 dns_mode: DnsProxyMode,
                 resolver: NetworkAddress,
                 timeout: int,
                 tcp_frag_size: int = DNS_TCP_FRAG_SIZE):
        self.dns_mode = dns_mode
        self.resolver = resolver
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
    def resolve_dot_static(message: Message, resolver: NetworkAddress, timeout: int, hostname:str, add_sni:bool = True) -> Message:
        """
        Resolves the given domain to an ip address using DNS over TLS on the given DNS resolver.
        :param message: the DNS message to resolve
        :param resolver: the DNS resolver to use
        :param timeout: the DNS request timeout
        :param hostname: the hostname of the DoT server, used in SNI
        :param add_sni: whether to add SNI
        :return: The Dns response by the resolver
        """
        if add_sni:
            return tls(message, where=resolver.host, port=resolver.port, timeout=timeout, server_hostname=hostname, verify=True)
        else:
            return tls(message, where=resolver.host, port=resolver.port, timeout=timeout)

    @staticmethod
    @fix_transaction_id
    def resolve_doh_static(message: Message, resolver: NetworkAddress, timeout: int, hostname: str, add_sni:bool = True) -> Message:
        """
        Resolves the given domain to an ip address using DNS over HTTPS on the given DNS resolver.
        :param message: the DNS message to resolve
        :param resolver: the DNS resolver to use
        :param timeout: the DNS request timeout
        :param hostname: the hostname that TLS should use in SNI
        :param add_sni: whether to add SNI
        :return: The Dns response by the resolver
        """
        # TODO: check http support through httpx dependency

        if add_sni:
            url=f"https://{resolver.host}:{resolver.port}/dns-query"

            (_, _, the_source) = _destination_and_source(
                resolver.host, resolver.port, None, 0, False
            )

            extensions = {}
            bootstrap_address = resolver.host
            extensions["sni_hostname"] = hostname
            q = message

            wire = q.to_wire()
            headers = {"accept": "application/dns-message"}

            if the_source is None:
                local_address = None
                local_port = 0
            else:
                local_address = the_source[0]
                local_port = the_source[1]

            transport = _HTTPTransport(
                local_address=local_address,
                http1=False,
                http2=True,
                verify=True,
                local_port=local_port,
                bootstrap_address=bootstrap_address,
                resolver=resolver,
                family=socket.AF_UNSPEC,
            )

            cm = httpx.Client(http1=False, http2=True, verify=True, transport=transport)

            with cm as session:
                headers.update(
                    {
                        "content-type": "application/dns-message",
                        "content-length": str(len(wire)),
                    }
                )
                response = session.post(
                    url,
                    headers=headers,
                    content=wire,
                    timeout=timeout,
                    extensions=extensions,
                )

            # status code exception
            if response.status_code < 200 or response.status_code > 299:
                raise ValueError(
                    f"{resolver.host} responded with status code {response.status_code}"
                    f"\nResponse body: {response.content}"
                )

            r = dns.message.from_wire(
                response.content,
                keyring=q.keyring,
                request_mac=q.request_mac,
                one_rr_per_rrset=False,
                ignore_trailing=False,
            )
            r.time = response.elapsed.total_seconds()
            if not q.is_response(r):
                raise BadResponse
            return r
        else:
            return https(message, where=resolver.host, port=resolver.port, http_version=HTTPVersion.H2, timeout=timeout)

    @staticmethod
    @fix_transaction_id
    def resolve_doh3_static(message: Message, resolver: NetworkAddress, timeout: int, hostname:str, add_sni:bool = True) -> Message:
        """
        Resolves the given domain to an ip address using DNS over HTTP3 on the given DNS resolver.
        :param message: the DNS message to resolve
        :param resolver: the DNS resolver to use
        :param timeout: the DNS request timeout
        :param hostname: the hostname of the DNS resolver to use in SNI
        :param add_sni: whether to add SNI
        :return: The Dns response by the resolver
        """
        # TODO: check quic support through aioquic dependency

        if add_sni:
            q = message
            where = resolver.host
            url = f"https://{resolver.host}:{resolver.port}/dns-query"

            q.id = 0
            wire = q.to_wire()
            manager = dns.quic.SyncQuicManager(
                verify_mode=True, server_name=hostname, h3=True
            )

            with manager:
                connection = manager.connect(where, resolver.port, None, 0)
                (start, expiration) = _compute_times(timeout)
                with connection.make_stream(timeout) as stream:
                    stream.send_h3(url, wire, True)
                    wire = stream.receive(_remaining(expiration))
                    _check_status(stream.headers(), where, wire)
                finish = time.time()

            r = dns.message.from_wire(
                wire,
                keyring=q.keyring,
                request_mac=q.request_mac,
                one_rr_per_rrset=False,
                ignore_trailing=False,
            )
            r.time = max(finish - start, 0.0)
            if not q.is_response(r):
                raise BadResponse
            return r
        else:
            return https(message, where=resolver.host, port=resolver.port, http_version=HTTPVersion.H3, timeout=timeout)

    @staticmethod
    @fix_transaction_id
    def resolve_doq_static(message: Message, resolver: NetworkAddress, timeout: int, hostname: str, add_sni:bool = True) -> Message:
        """
        Resolves the given domain to an ip address using DNS over QUIC on the given DNS resolver.
        :param message: the DNS message to resolve
        :param resolver: the DNS resolver to use
        :param timeout: the DNS request timeout
        :param hostname: hostname of the DoQ server, used in SNI
        :param add_sni: whether to add SNI
        :return: The Dns response by the resolver
        """
        # TODO: check quic support through aioquic dependency
        if add_sni:
            return quic(message, where=resolver.host, port=resolver.port, timeout = timeout, server_hostname=hostname, hostname=hostname, verify=True)
        else:
            return quic(message, where=resolver.host, port=resolver.port, timeout=timeout)

    @staticmethod
    def resolve_udp_static(message: Message, resolver: NetworkAddress, timeout: int) -> Message:
        """
        Resolves the given domain to an ip address using DNS over UDP on the given DNS resolver.
        :param message: the DNS message to resolve
        :param resolver: the DNS resolver
        :param timeout: the DNS request timeout
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

    @staticmethod
    def resolve_static(mode: DnsProxyMode, message: Message, resolver: NetworkAddress, timeout: int, frag_size: int=DNS_TCP_FRAG_SIZE, hostname: str="", add_sni:bool = True) -> Message:
        """
        Resolves the requested message based on the selected mode.
        :param mode: the DNS proxy mode to use. Must not be AUTO, will raise a DnsException
        :param message: the DNS message to resolve
        :param resolver: the DNS resolver
        :param timeout: the DNS request timeout
        :param frag_size: size of the TCP segments used to fragment the DNS message if the mode is TCP_FRAG
        :param hostname: the hostname of the DNS resolver
        :param add_sni: whether to add SNI
        """
        if mode == DnsProxyMode.AUTO:
            raise DnsException("No resolution function for mode AUTO")
        elif mode == DnsProxyMode.DOT:
            return DomainResolver.resolve_dot_static(message, resolver=resolver, timeout=timeout, hostname=hostname, add_sni=add_sni)
        elif mode == DnsProxyMode.DOH:
            return DomainResolver.resolve_doh_static(message, resolver=resolver, timeout=timeout, hostname=hostname, add_sni=add_sni)
        elif mode == DnsProxyMode.DOH3:
            return DomainResolver.resolve_doh3_static(message, resolver=resolver, timeout=timeout, hostname=hostname, add_sni=add_sni)
        elif mode == DnsProxyMode.DOQ:
            return DomainResolver.resolve_doq_static(message, resolver=resolver, timeout=timeout, hostname=hostname, add_sni=add_sni)
        elif mode == DnsProxyMode.UDP:
            return DomainResolver.resolve_udp_static(message, resolver=resolver, timeout=timeout)
        elif mode == DnsProxyMode.TCP:
            return DomainResolver.resolve_tcp_static(message, resolver=resolver, timeout=timeout)
        elif mode == DnsProxyMode.TCP_FRAG:
            return DomainResolver.resolve_tcp_frag_static(message, resolver=resolver, timeout=timeout, frag_size=frag_size)
        elif mode == DnsProxyMode.LAST_RESPONSE:
            return DomainResolver.resolve_last_response_static(message, resolver=resolver, timeout=timeout)
        else:
            raise DnsException(f"Unknown mode {mode}")

    def resolve(self, message: Message) -> Message:
        """
        Resolves the given DNS message using the configured mode on the configured provider using the configured
        timeout and frag size.
        """
        return DomainResolver.resolve_static(mode=self.dns_mode, message=message, resolver=self.resolver, timeout=self.timeout, frag_size=self.tcp_frag_size)

    def works(self, message: Message) -> bool:
        """
        Determines if the configures resolver is consistently reachable, returns true if at least 3 out of 5 connection
        attempts worked.
        """
        working = 0
        for _ in range(DomainResolver.TRIES_CONFIRM_WORKING):
            try:
                self.resolve(message=message)
            except DnsException as _:
                pass
            else:
                working += 1
        return working >= DomainResolver.THRESHOLD_CONFIRM_WORKING

    def __str__(self):
        return f"{self.dns_mode} - {self.resolver}"
