import logging
import socket

from enumerators.ProxyMode import ProxyMode
from exception.ParserException import ParserException
from network.DomainResolver import DomainResolver
from network.Forwarder import Forwarder
from network.NetworkAddress import NetworkAddress
from network.WrappedSocket import WrappedSocket
from network.protocols.http import Http
from network.protocols.socks import Socks
from network.protocols.tls import Tls
from util.Util import is_valid_ipv4_address
from util.constants import STANDARD_SOCKET_RECEIVE_SIZE, TLS_1_0_HEADER, TLS_1_2_HEADER, \
    TLS_1_1_HEADER, SOCKSv4_HEADER


class ConnectionHandler:
    """
    Handles a single client connection of the proxy server.
    """

    def __init__(self,
                 connection_socket: WrappedSocket,
                 address: NetworkAddress,
                 timeout: int,
                 record_frag: bool,
                 tcp_frag: bool,
                 frag_size: int,
                 dot_ip: str,
                 disabled_modes: list[ProxyMode],
                 forward_proxy: NetworkAddress,
                 forward_proxy_mode: ProxyMode,
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
        except ParserException as e:
            logging.warning(f"Could not parse initial proxy message with {e}. Stopping!")
            return

        self.send_proxy_answer(http_version)

        # resolve domain if no forward proxy or the forward proxy needs a resolved address
        if (not is_valid_ipv4_address(final_server_address.host)) and \
                (self.forward_proxy_resolve_address or self.forward_proxy is None):
            if self.dot_ip:
                host = DomainResolver.resolve_over_dot(final_server_address.host, self.dot_ip)
            else:
                host = DomainResolver.resolve_plain(final_server_address.host)
            self.debug(f"Resolved {host} from {final_server_address.host}")
            final_server_address.host = host

        # set correct target
        if self.forward_proxy is None:
            target_address = (final_server_address.host, final_server_address.port)
        else:
            target_address = (self.forward_proxy.host, self.forward_proxy.port)
            self.debug(f"Using forward proxy {target_address}")

        # open socket to server
        server_socket = socket.create_connection(target_address)
        if self.tcp_frag and self.record_frag:
            # align record and tcp fragment size
            server_socket = WrappedSocket(self.timeout, server_socket, self.frag_size + 5)
        elif self.tcp_frag:
            server_socket = WrappedSocket(self.timeout, server_socket, self.frag_size)
        else:
            server_socket = WrappedSocket(self.timeout, server_socket)
        logging.info(f"Connected {final_server_address.host}:{final_server_address.port} "
                     f"to {target_address[0]}:{target_address[1]}")

        if self.forward_proxy is not None:
            self.connect_forward_proxy(server_socket, final_server_address, http_version)

        # start proxying
        Forwarder(self.connection_socket, self.address.__str__(), server_socket,
                  f"{target_address[0]}:{target_address[1]}", self.record_frag, self.frag_size).start()

    def get_proxy_mode(self) -> ProxyMode:
        """
        Determines the mode of the proxy based on the first client message
        """
        header = self.connection_socket.peek(16)

        if header.startswith(TLS_1_0_HEADER) or header.startswith(TLS_1_1_HEADER) \
                or header.startswith(TLS_1_2_HEADER):
            self.debug("Determined SNI Proxy Request")
            return ProxyMode.SNI

        if header.startswith(SOCKSv4_HEADER):
            self.debug("Determined SOCKSv4 Proxy Request")
            return ProxyMode.SOCKSv4

        try:
            ascii_decoded_header = header.decode('ASCII')
        except UnicodeDecodeError as e:
            raise ParserException(f"Could not determine message type of message {header}")
        else:
            if ascii_decoded_header.upper().startswith('GET '):
                self.debug("Determined HTTP Proxy Request")
                return ProxyMode.HTTP
            elif ascii_decoded_header.upper().startswith('CONNECT '):
                self.debug("Determined HTTPS Proxy Request")
                return ProxyMode.HTTPS

        raise ParserException(f"Could not determine message type of message {header}")

    def get_destination_address(self) -> (NetworkAddress, str):
        """
        Reads a proxy destination address and returns the host and port of the destination.
        :return: Host, port, and optional http version of the destination server
        """
        http_version = None
        if self.proxy_mode == ProxyMode.HTTP:
            host, port, http_version = Http.read_http_get(self.connection_socket)
            self.debug(f"Read host {host} and port {port} from HTTP GET")
        elif self.proxy_mode == ProxyMode.HTTPS:
            host, port, http_version = Http.read_http_connect(self.connection_socket)
            self.debug(f"Read host {host} and port {port} from HTTP CONNECT")
        elif self.proxy_mode == ProxyMode.SNI:
            host, port = Tls.read_sni(self.connection_socket, self.timeout), 443
            self.debug(f"Read host {host} and port {port} from SNI")
        elif self.proxy_mode == ProxyMode.SOCKSv4:
            host, port = Socks.read_socks4(self.connection_socket)
            self.debug(f"Read host {host} and port {port} from SOCKSv4")
        else:
            raise ParserException("Unknown proxy type")
        return NetworkAddress(host, port), http_version

    def send_proxy_answer(self, http_version: str):
        if self.proxy_mode == ProxyMode.HTTPS:
            # answer with 200 OK
            self.connection_socket.send(Http.http_200_ok(http_version))
        elif self.proxy_mode == ProxyMode.SOCKSv4:
            # answer with Socksv4 okay
            self.connection_socket.send(Socks.socks4_ok())

    def connect_forward_proxy(self, server_socket: WrappedSocket,
                              final_server_address: NetworkAddress,
                              http_version: str):
        try:
            # send proxy messages if necessary
            if self.forward_proxy_mode == ProxyMode.HTTPS:
                server_socket.send(Http.connect_message(final_server_address, http_version))
                self.debug(f"Send HTTP CONNECT to forward proxy")
                # receive HTTP 200 OK
                answer = server_socket.recv(STANDARD_SOCKET_RECEIVE_SIZE)
                if not answer.upper().startswith(Http.http_200_ok(http_version)):
                    self.debug(f"Forward proxy rejected the connection with {answer}")
            elif self.forward_proxy == ProxyMode.SOCKSv4:
                server_socket.send(Socks.socks4_request(final_server_address))
                self.debug(f"Send SOCKSv4 to forward proxy")
                # receive SOCKSv4 OK
                answer = server_socket.recv(STANDARD_SOCKET_RECEIVE_SIZE)
                if not answer.upper().startswith(Socks.socks4_ok()) and len(answer) != 8:
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
