import logging
import socket
import threading

from enumerators.ProxyMode import ProxyMode
from exception.ParserException import ParserException
from network.NetworkAddress import NetworkAddress
from network.WrappedSocket import WrappedSocket
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
        # TODO: continue here
        if not is_valid_ipv4_address(final_server_address.host) and \
                (self.forward_proxy_resolve_address or self.forward_proxy is None):
            _host = host
            host = self.resolve_domain(host)
            Proxy.debug(f"Resolved {host} from {_host}", f"{address[0]}:{address[1]}")

        # set correct target
        if self.forward_proxy is None:
            target_address = (host, port)
        else:
            target_address = (self.forward_proxy.host, self.forward_proxy.port)
            Proxy.debug(f"Using forward proxy {target_address}", f"{address[0]}:{address[1]}")

        # open socket to server
        server_socket = socket.create_connection(target_address)
        if self.tcp_frag and self.record_frag:
            # align record and tcp fragment size
            server_socket = WrappedSocket(self.timeout, server_socket, self.frag_size + 5)
        elif self.tcp_frag:
            server_socket = WrappedSocket(self.timeout, server_socket, self.frag_size)
        else:
            server_socket = WrappedSocket(self.timeout, server_socket)
        logging.info(f"Connected {address[0]}:{address[1]} to {target_address[0]}:{target_address[1]}")

        try:
            # send proxy messages if necessary
            # TODO: also support proxy authentication?
            if self.forward_proxy is not None and self.forward_proxy.mode == ProxyMode.HTTPS \
                    and needs_proxy_message:
                server_socket.send(f'CONNECT {host}:{port} HTTP/1.1\nHost: {host}:{port}\n\n'
                                   .encode('ASCII'))
                Proxy.debug(f"Send HTTP CONNECT to forward proxy", f"{address[0]}:{address[1]}")
                # receive HTTP 200 OK
                answer = server_socket.recv(STANDARD_SOCKET_RECEIVE_SIZE)
                if not answer.startswith(HTTP_200_RESPONSE):
                    Proxy.debug(f"Forward proxy rejected the connection with {answer}", f"{address[0]}:{address[1]}")
        except:
            Proxy.debug("Could not send proxy message", f"{address[0]}:{address[1]}")
            client_socket.try_close()
            logging.info(f"Closed connections of {address[0]}:{address[1]}")
            return

        # start proxying
        (threading.Thread(target=self.forward, args=(client_socket,
                                                     server_socket,
                                                     f"{address[0]}:{address[1]}->{target_address[0]}:{target_address[1]}",
                                                     self.record_frag)).start())
        threading.Thread(target=self.forward, args=(server_socket,
                                                    client_socket,
                                                    f"{target_address[0]}:{target_address[1]}->{address[0]}:{address[1]}",
                                                    )).start()

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
            host, port = self.connection_socket.read_http_get()
            self.debug(f"Read host {host} and port {port} from HTTP GET")
        elif self.proxy_mode == ProxyMode.HTTPS:
            host, port = self.connection_socket.read_http_connect()
            self.debug(f"Read host {host} and port {port} from HTTP CONNECT")
        elif self.proxy_mode == ProxyMode.SNI:
            host, port = self.connection_socket.read_sni(), 443
            self.debug(f"Read host {host} and port {port} from SNI")
        else:
            raise ParserException("Unknown proxy type")
        return NetworkAddress(host, port)

    # LOGGER utility functions
    def _logger_string(self, message) -> str:
        return f"{self.address.host}->{self.address.port}: {message}"

    def debug(self, message: str):
        logging.debug(self._logger_string(message))

    def warn(self, message: str):
        logging.warning(self._logger_string(message))

    def error(self, message: str):
        logging.error(self._logger_string(message))

    def info(self, message: str):
        logging.info(self._logger_string(message))
