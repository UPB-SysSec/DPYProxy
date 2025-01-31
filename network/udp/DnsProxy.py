import logging
import select
import socket
import threading

from enumerators.DnsProxyMode import DnsProxyMode
from exception.DnsException import DnsException
from network.DomainResolver import DomainResolver
from network.NetworkAddress import NetworkAddress
from network.WrappedSocket import WrappedSocket
from network.protocols.Dns import Dns


class DnsProxy:
    """
    Proxy server
    """

    # TODO: import from config file / determine during auto mode
    RESOLVER = NetworkAddress("9.9.9.9", 0)

    def __init__(self, address: NetworkAddress,
                 timeout: int = 2,
                 proxy_mode: DnsProxyMode = DnsProxyMode.AUTO):
        # timeout for socket reads and message reception
        self.timeout = timeout
        self.address = address
        self.proxy_mode = proxy_mode
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.settimeout(self.timeout)
        self.continue_processing = True
        # initialized in start()
        self.domain_resolver: DomainResolver|None = None


    def handle(self, message: bytes):

        # receive message from client

        try:
            message = Dns.read_dns(message)
        except DnsException as e:
            logging.error(f"Could not parse DNS message: {e}")
            return


        if self.proxy_mode == DnsProxyMode.AUTO:
            logging.error("Proxy mode has not been set after automatic discovery.")
            return
        elif self.proxy_mode == DnsProxyMode.UDP:
            answer = self.domain_resolver.resolve_udp(message)
        elif self.proxy_mode == DnsProxyMode.DOH:
            answer = self.domain_resolver.resolve_doh(message)
        elif self.proxy_mode == DnsProxyMode.DOT:
            answer = self.domain_resolver.resolve_dot(message)
        elif self.proxy_mode == DnsProxyMode.DOQ:
            answer = self.domain_resolver.resolve_doq(message)
        elif self.proxy_mode == DnsProxyMode.TCP:
            answer = self.domain_resolver.resolve_tcp(message)
        elif self.proxy_mode == DnsProxyMode.TCP_FRAG:
            answer = self.domain_resolver.resolve_tcp_frag(message)
        elif self.proxy_mode == DnsProxyMode.CHINA:
            answer = self.domain_resolver.resolve_china(message)
        else:
            logging.error("Unknown proxy mode.")
            return

        client_socket.socket.send(answer.to_wire())

    def start(self):
        """
        Starts the proxy. After calling the proxy is listening for connections.
        :return:
        """
        if self.proxy_mode == DnsProxyMode.AUTO:
            logging.info("Automatic mode not implemented yet.")
            # self.proxy_mode = determine_mode()
            # TODO implement automatic mode

        self.domain_resolver = DomainResolver(udp_dns_resolver=DnsProxy.RESOLVER,
                                             tcp_dns_resolver=DnsProxy.RESOLVER,
                                             tcp_frag_dns_resolver=DnsProxy.RESOLVER,
                                             doh_dns_resolver=DnsProxy.RESOLVER,
                                             doq_dns_resolver=DnsProxy.RESOLVER,
                                             dot_dns_resolver=DnsProxy.RESOLVER,
                                             dns_mode=self.proxy_mode)

        # opening server socket
        self.server.bind((self.address.host, self.address.port))
        # TODO: make UDP / TCP specifiable
        print(f"### Started UDP proxy on {self.address.host}:{self.address.port} ###")

        while self.continue_processing:
            readable, _, _ = select.select([self.server], [], [], 1)
            if not readable:
                continue
            # listen for incoming connections
            message, address = self.server.recvfrom(Dns.DNS_MAX_SIZE * 4)
            address = NetworkAddress(address[0], address[1])
            logging.info(f"request from {address.host}:{address.port}")
            # spawn a new thread that runs the function handle()
            threading.Thread(target=self.handle, args=(message, address)).start()
        logging.info("### Stopped proxy ###")
