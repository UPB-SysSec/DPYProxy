import logging
import socket

from enumerators.TcpProxyMode import TcpProxyMode
from exception.ParserException import ParserException
from network.DomainResolver import DomainResolver
from network.Forwarder import Forwarder
from network.NetworkAddress import NetworkAddress
from network.tcp.WrappedTcpSocket import WrappedTcpSocket
from network.protocols.Dns import Dns
from network.protocols.Http import Http
from network.protocols.Socksv4 import Socksv4
from network.protocols.Socksv5 import Socksv5
from network.protocols.Tls import Tls
from util.Util import is_valid_ipv4_address
from util.constants import STANDARD_SOCKET_RECEIVE_SIZE, TLS_1_0_HEADER, TLS_1_2_HEADER, \
    TLS_1_1_HEADER, SOCKSv4_HEADER, SOCKSv5_HEADER


class TcpConnectionHandler:
    """
    Handles a single client connection of the proxy server.
    """

    def __init__(self,
                 connection_socket: WrappedTcpSocket,
                 address: NetworkAddress,
                 timeout: int,
                 record_frag: bool,
                 tcp_frag: bool,
                 frag_size: int,
                 dot_ip: str,
                 disabled_modes: list[TcpProxyMode],
                 forward_proxy: NetworkAddress,
                 forward_proxy_mode: TcpProxyMode,
                 forward_proxy_resolve_address: bool):
        self.connection_socket = connection_socket
        self.address = address
        self.proxy_mode = None
        self.timeout = timeout
        self.record_frag = record_frag
        self.tcp_frag = tcp_frag
        self.frag_size = frag_size
        self.dot_ip = dot_ip
        self.disabled_modes = disabled_modes
        self.forward_proxy = forward_proxy
        self.forward_proxy_mode = forward_proxy_mode
        self.forward_proxy_resolve_address = forward_proxy_resolve_address

    def handle(self):
        """
        Handles the connection to a single client.
        :return: None
        """
        # determine proxy mode / message type
        self.proxy_mode = self.get_proxy_mode()
        if self.proxy_mode in self.disabled_modes:
            self.info(f"Proxy mode {self.proxy_mode} is disabled. Stopping!")
            return

        # determine destination address
        try:
            final_server_address, http_version = self.get_destination_address()
            # TODO: If ProxyMode.DNS then also get resolve target
        except ParserException as e:
            logging.warning(f"Could not parse initial proxy message with {e}. Stopping!")
            return

        # TODO: If ProxyMode.DNS then this should probably be done via selected circumvention method also
        # resolve domain if no forward proxy or the forward proxy needs a resolved address
        if (not is_valid_ipv4_address(final_server_address.host)) and \
                (self.forward_proxy_resolve_address or self.forward_proxy is None):
            if self.dot_ip:
                host = DomainResolver.resolve_over_dot(final_server_address.host, self.dot_ip)
            else:
                host = DomainResolver.resolve_plain(final_server_address.host)
            self.debug(f"Resolved {host} from {final_server_address.host}")
            final_server_address.host = host

        # TODO: If ProxyMode.DNS and DoT/DoH/DoQ selected, this should be respective target directly
        # set correct target
        if self.forward_proxy is None:
            target_address = (final_server_address.host, final_server_address.port)
        else:
            target_address = (self.forward_proxy.host, self.forward_proxy.port)
            self.debug(f"Using forward proxy {target_address}")

        # open socket to server
        # TODO: If ProxyMode.DNS then this should be UDP with circumventions or separate DoT/DoQ/DoH requests
        try:
            server_socket = socket.create_connection(target_address)
        except Exception as e:
            self.info(f"Could not connect to server due to {e}.")
            self.connection_socket.try_close()
            return
        if self.tcp_frag and self.record_frag:
            # align record and tcp fragment size
            server_socket = WrappedTcpSocket(self.timeout, server_socket, self.frag_size + 5)
        elif self.tcp_frag:
            server_socket = WrappedTcpSocket(self.timeout, server_socket, self.frag_size)
        else:
            server_socket = WrappedTcpSocket(self.timeout, server_socket)
        logging.info(f"Connected {final_server_address.host}:{final_server_address.port} "
                     f"to {target_address[0]}:{target_address[1]}")

        self.send_proxy_answer(http_version, server_socket)

        if self.forward_proxy is not None:
            self.connect_forward_proxy(server_socket, final_server_address, http_version)

        # TODO: If ProxyMode.DNS then we probably do not need a forwarder once we obtain the correct DNS entry?
        # start proxying
        Forwarder(self.connection_socket, self.address.__str__(), server_socket,
                  f"{target_address[0]}:{target_address[1]}", self.record_frag, self.frag_size).start()

    def get_proxy_mode(self) -> TcpProxyMode:
        """
        Determines the mode of the proxy based on the first client message
        """
        header = self.connection_socket.peek(3)

        if header.startswith(TLS_1_0_HEADER) or header.startswith(TLS_1_1_HEADER) \
                or header.startswith(TLS_1_2_HEADER):
            self.debug("Determined SNI Proxy Request")
            return TcpProxyMode.SNI

        if header.startswith(SOCKSv4_HEADER):
            self.debug("Determined SOCKSv4 Proxy Request")
            return TcpProxyMode.SOCKSv4

        if header.startswith(SOCKSv5_HEADER):
            self.debug("Determined SOCKSv5 Proxy Request")
            return TcpProxyMode.SOCKSv5

        try:
            ascii_decoded_header = header.decode('ASCII')
        except UnicodeDecodeError as e:
            raise ParserException(f"Could not determine message type of message {header}")
        else:
            if ascii_decoded_header.upper().startswith('CON'):
                self.debug("Determined HTTPS Proxy Request")
                return TcpProxyMode.HTTPS
            else:
                # assume we have http
                self.debug("Determined HTTP Proxy Request")
                return TcpProxyMode.HTTP

    def get_destination_address(self) -> (NetworkAddress, str):
        """
        Reads a proxy destination address and returns the host and port of the destination.
        :return: Host, port, and optional http version of the destination server
        """
        http_version = None
        if self.proxy_mode == TcpProxyMode.HTTP:
            host, port, http_version = Http.read_http_get(self.connection_socket)
            self.debug(f"Read host {host} and port {port} from HTTP GET")
        elif self.proxy_mode == TcpProxyMode.HTTPS:
            host, port, http_version = Http.read_http_connect(self.connection_socket)
            self.debug(f"Read host {host} and port {port} from HTTP CONNECT")
        elif self.proxy_mode == TcpProxyMode.SNI:
            host, port = Tls.read_sni(self.connection_socket, self.timeout), 443
            self.debug(f"Read host {host} and port {port} from SNI")
        elif self.proxy_mode == TcpProxyMode.SOCKSv4:
            host, port = Socksv4.read_socks4(self.connection_socket)
            self.debug(f"Read host {host} and port {port} from SOCKSv4")
        elif self.proxy_mode == TcpProxyMode.SOCKSv5:
            host, port = Socksv5.read_socks5(self.connection_socket)
            self.debug(f"Read host {host} and port {port} from SOCKSv5")
        elif self.proxy_mode == TcpProxyMode.DNS:
            host, port = Dns.read_dns(self.connection_socket)
            self.debug(f"Read host {host} and port {port} from DNS")
        else:
            raise ParserException("Unknown proxy type")
        return NetworkAddress(host, port), http_version

    def send_proxy_answer(self, http_version: str, server_socket: WrappedTcpSocket):
        if self.proxy_mode == TcpProxyMode.HTTPS:
            # answer with 200 OK
            self.connection_socket.send(Http.http_200_ok(http_version))
        elif self.proxy_mode == TcpProxyMode.SOCKSv4:
            # answer with Socksv4 okay
            self.connection_socket.send(Socksv4.socks4_ok())
        elif self.proxy_mode == TcpProxyMode.SOCKSv5:
            # answer with Socksv5 okay
            self.connection_socket.send(Socksv5.socks5_ok(server_socket))

    def connect_forward_proxy(self, server_socket: WrappedTcpSocket,
                              final_server_address: NetworkAddress,
                              http_version: str):
        try:
            # send proxy messages if necessary
            if self.forward_proxy_mode == TcpProxyMode.HTTPS:
                server_socket.send(Http.connect_message(final_server_address, http_version))
                self.debug(f"Sent HTTP CONNECT to forward proxy")
                # receive HTTP 200 OK
                answer = server_socket.recv(STANDARD_SOCKET_RECEIVE_SIZE)
                if not answer.upper().startswith(Http.http_200_ok(http_version)):
                    raise ParserException(f"Forward proxy rejected the connection with {answer}")

            elif self.forward_proxy == TcpProxyMode.SOCKSv4:
                server_socket.send(Socksv4.socks4_request(final_server_address))
                self.debug(f"Sent SOCKSv4 to forward proxy")
                # receive SOCKSv4 OK
                answer = server_socket.recv(STANDARD_SOCKET_RECEIVE_SIZE)
                if not answer.upper().startswith(Socksv4.socks4_ok()) and len(answer) != 8:
                    raise ParserException(f"Forward proxy rejected the connection with {answer}")

            elif self.forward_proxy == TcpProxyMode.SOCKSv5:
                server_socket.send(Socksv5.socks5_auth_methods())
                self.debug("Sent SOCKSv5 auth methods")
                answer = server_socket.recv(2)
                if answer == b'\x05\xFF':
                    raise ParserException("Forward proxy does not support no auth")
                if answer != b'\x05\x00':
                    raise ParserException(f"Forward proxy rejected the connection with {answer}")
                server_socket.send(Socksv5.socks5_request(final_server_address))
                self.debug(f"Sent SOCKSv5 to forward proxy")
                # receive SOCKSv5 OK
                answer = server_socket.recv(STANDARD_SOCKET_RECEIVE_SIZE)
                if not answer.upper().startswith(Socksv5.socks5_ok(server_socket)):
                    self.debug(f"Forward proxy rejected the connection with {answer}")
        except:
            self.debug("Could not send proxy message")
            self.connection_socket.try_close()
            logging.info(f"Closed connections")
            return

    # LOGGER utility functions
    def _logger_string(self, message: str) -> str:
        return f"{self.address.host}:{self.address.port}: {message}"

    def debug(self, message: str):
        logging.debug(self._logger_string(message))

    def warn(self, message: str):
        logging.warning(self._logger_string(message))

    def error(self, message: str):
        logging.error(self._logger_string(message))

    def info(self, message: str):
        logging.info(self._logger_string(message))
