import logging
import select
import socket
import threading

from enumerators.DnsProxyMode import DnsProxyMode
from network.NetworkAddress import NetworkAddress
from network.WrappedSocket import WrappedSocket


class DnsProxy:
    """
    Proxy server
    """

    def __init__(self, address: NetworkAddress,
                 timeout: int = 120,
                 proxy_mode: DnsProxyMode = DnsProxyMode.AUTO):
        # timeout for socket reads and message reception
        self.timeout = timeout
        self.address = address
        self.proxy_mode = proxy_mode
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.continue_processing = True


    def handle(self, client_socket: WrappedSocket, address: NetworkAddress):
        if self.proxy_mode == DnsProxyMode.AUTO:
            logging.error("Proxy mode has not been set after automatic discovery.")
            return
        elif self.proxy_mode == DnsProxyMode.DOH:
            # TODO: implement DoH mode
            pass
        elif self.proxy_mode == DnsProxyMode.DOT:
            # TODO: implement DoT mode
            pass
        elif self.proxy_mode == DnsProxyMode.DOQ:
            # TODO: implement DoQ mode
            pass
        elif self.proxy_mode == DnsProxyMode.TCP:
            # TODO: implement TCP mode
            pass
        elif self.proxy_mode == DnsProxyMode.TCP_FRAG:
            # TODO: implement TCP fragmentation mode
            pass
        elif self.proxy_mode == DnsProxyMode.CHINA:
            # TODO: implement China mode
            pass
        else:
            logging.error("Unknown proxy mode.")
            return
        # call correct module that forwards DNS request and returns response

    def start(self):
        """
        Starts the proxy. After calling the proxy is listening for connections.
        :return:
        """
        if self.proxy_mode == DnsProxyMode.AUTO:
            logging.info("Automatic mode not implemented yet.")
            # self.proxy_mode = determine_mode()
            # TODO implement automatic mode

        # opening server socket
        self.server.bind((self.address.host, self.address.port))
        self.server.listen()
        print(f"### Started UDP proxy on {self.address.host}:{self.address.port} ###")
        while self.continue_processing:
            readable, _, _ = select.select([self.server], [], [], 1)
            if not readable:
                continue
            # listen for incoming connections
            client_socket, address = self.server.accept()
            address = NetworkAddress(address[0], address[1])
            client_socket = WrappedSocket(self.timeout, client_socket)
            logging.info(f"request from {address.host}:{address.port}")
            # spawn a new thread that runs the function handle()
            threading.Thread(target=self.handle, args=(client_socket, address)).start()
        logging.info("### Stopped proxy ###")
