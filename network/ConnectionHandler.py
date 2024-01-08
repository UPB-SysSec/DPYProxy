import logging
import socket

from enumerators.ProxyMode import ProxyMode
from exception.ParserException import ParserException
from network.DomainResolver import DomainResolver
from network.Forwarder import Forwarder
from network.NetworkAddress import NetworkAddress
from network.WrappedSocket import WrappedSocket
from network.protocols.http import HttpParser
from network.protocols.tls import TlsParser
from util.Util import is_valid_ipv4_address
from util.constants import STANDARD_SOCKET_RECEIVE_SIZE, HTTP_200_RESPONSE, TLS_1_0_HEADER, TLS_1_2_HEADER, \
    TLS_1_1_HEADER


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

        if self.proxy_mode == ProxyMode.HTTPS:
            # answer with 200 OK
            self.connection_socket.send(HTTP_200_RESPONSE)

        # determine destination address
        try:
            final_server_address = self.get_destination_address()
        except ParserException as e:
            logging.warning(f"Could not parse initial proxy message with {e}. Stopping!")
            return

        # resolve domain if no forward proxy or the forward proxy needs a resolved address
        if not is_valid_ipv4_address(final_server_address.host) and \
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

        try:
            # send proxy messages if necessary
            if self.forward_proxy is not None and self.forward_proxy_mode == ProxyMode.HTTPS:
                server_socket.send(f'CONNECT {final_server_address.host}:{final_server_address.port} HTTP/1.1\n'
                                   f'Host: {final_server_address.host}:{final_server_address.port}\n\n'
                                   .encode('ASCII'))
                self.debug(f"Send HTTP CONNECT to forward proxy")
                # receive HTTP 200 OK
                answer = server_socket.recv(STANDARD_SOCKET_RECEIVE_SIZE)
                if not answer.upper().startswith(HTTP_200_RESPONSE):
                    self.debug(f"Forward proxy rejected the connection with {answer}")
        except:
            self.debug("Could not send proxy message")
            self.connection_socket.try_close()
            logging.info(f"Closed connections")
            return

        # start proxying
        Forwarder(self.connection_socket, self.address.__str__(), server_socket,
                  f"{target_address[0]}:{target_address[1]}", self.record_frag, self.frag_size).start()

    def get_proxy_mode(self) -> ProxyMode:
        """
        Determines the mode of the proxy based on the first client message
        """
        header = self.connection_socket.peek(16)
        try:
            ascii_decoded_header = header.decode('ASCII')
        except UnicodeDecodeError as e:
            if header.startswith(TLS_1_0_HEADER) or header.startswith(TLS_1_1_HEADER) \
                    or header.startswith(TLS_1_2_HEADER):
                self.debug("Determined SNI Proxy Request")
                return ProxyMode.SNI
        else:
            if ascii_decoded_header.upper().startswith('GET '):
                self.debug("Determined HTTP Proxy Request")
                return ProxyMode.HTTP
            elif ascii_decoded_header.upper().startswith('CONNECT '):
                self.debug("Determined HTTPS Proxy Request")
                return ProxyMode.HTTPS

        raise ParserException(f"Could not determine message type of message {header}")

    def get_destination_address(self) -> NetworkAddress:
        """
        Reads a proxy destination address and returns the host and port of the destination.
        :return: Host and port of the destination server
        """
        if self.proxy_mode == ProxyMode.HTTP:
            host, port = HttpParser.read_http_get(self.connection_socket)
            self.debug(f"Read host {host} and port {port} from HTTP GET")
        elif self.proxy_mode == ProxyMode.HTTPS:
            host, port = HttpParser.read_http_connect(self.connection_socket)
            self.debug(f"Read host {host} and port {port} from HTTP CONNECT")
        elif self.proxy_mode == ProxyMode.SNI:
            host, port = TlsParser.read_sni(self.connection_socket, self.timeout), 443
            self.debug(f"Read host {host} and port {port} from SNI")
        else:
            raise ParserException("Unknown proxy type")
        return NetworkAddress(host, port)

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
