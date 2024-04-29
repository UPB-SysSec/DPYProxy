import logging
import socket
import threading

from enumerators.NetworkType import NetworkType
from enumerators.ProxyMode import ProxyMode
from network.ConnectionHandler import ConnectionHandler
from network.NetworkAddress import NetworkAddress
from network.WrappedSocket import WrappedSocket


class Proxy:
    """
    Proxy server
    """

    def __init__(self, address: NetworkAddress,
                 timeout: int = 120,
                 record_frag: bool = False,
                 tcp_frag: bool = False,
                 frag_size: int = 20,
                 dot_ip: str = "8.8.4.4",
                 network_type: NetworkType = NetworkType.DUAL_STACK,
                 disabled_modes: list[ProxyMode] = None,
                 forward_proxy: NetworkAddress = None,
                 forward_proxy_mode: ProxyMode = ProxyMode.HTTPS,
                 forward_proxy_resolve_address: bool = False):
        # timeout for socket reads and message reception
        self.timeout = timeout
        # own port
        self.address = address
        # record fragmentation settings
        self.record_frag = record_frag
        self.tcp_frag = tcp_frag
        self.frag_size = frag_size
        # whether to use dot for domain resolution
        self.dot_ip = dot_ip
        self.network_type = network_type
        self.disabled_modes = disabled_modes
        if self.disabled_modes is None:
            self.disabled_modes = []
        # settings for another proxy to contact further down the line
        self.forward_proxy = forward_proxy
        self.forward_proxy_mode = forward_proxy_mode
        self.forward_proxy_resolve_address = forward_proxy_resolve_address
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def handle(self, client_socket: WrappedSocket, address: NetworkAddress):
        ConnectionHandler(
            client_socket,
            address,
            self.timeout,
            self.record_frag,
            self.tcp_frag,
            self.frag_size,
            self.dot_ip,
            self.network_type,
            self.disabled_modes,
            self.forward_proxy,
            self.forward_proxy_mode,
            self.forward_proxy_resolve_address
        ).handle()

    def start(self):
        """
        Starts the proxy. After calling the proxy is listening for connections.
        :return:
        """
        # opening server socket
        self.server.bind((self.address.host, self.address.port))
        self.server.listen()
        print(f"### Started proxy on {self.address.host}:{self.address.port} ###")
        if self.dot_ip:
            logging.debug(f"Using DoT resolver {self.dot_ip}")
        if self.forward_proxy:
            logging.debug(f"Using forward proxy {self.forward_proxy}")
        while True:  # listen for incoming connections
            client_socket, address = self.server.accept()
            address = NetworkAddress(address[0], address[1])
            client_socket = WrappedSocket(self.timeout, client_socket)
            logging.info(f"request from {address.host}:{address.port}")
            # spawn a new thread that runs the function handle()
            threading.Thread(target=self.handle, args=(client_socket, address)).start()
