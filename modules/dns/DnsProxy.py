import logging
import select
import socket
import threading
import traceback

from dns.rcode import SERVFAIL

from enumerators.DnsProxyMode import DnsProxyMode
from exception.DnsException import DnsException
from modules.dns.DnsModeDeterminator import DnsModeDeterminator
from network.DomainResolver import DomainResolver
from network.NetworkAddress import NetworkAddress
from network.protocols.Dns import Dns


class DnsProxy:
    """
    Proxy server
    """

    # TODO: import from config file / determine during auto mode
    DOT_RESOLVER = NetworkAddress("9.9.9.9", 853)
    DOH_RESOLVER = NetworkAddress("1.1.1.1", 443)
    DOH3_RESOLVER = NetworkAddress("1.1.1.1", 443)
    UDP_RESOLVER = NetworkAddress("1.1.1.1", 53)
    TCP_RESOLVER = NetworkAddress("1.1.1.1", 53)
    DOQ_RESOLVER = NetworkAddress("94.140.15.16", 443)

    # TODO: make specifiable?

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


    def handle(self, message: bytes, address: NetworkAddress):
        # receive message from client
        try:
            message = Dns.read_dns(message)
            logging.debug(f"{address.host}:{address.port}: parsed dns message:\n{message}")
        except DnsException as e:
            logging.error(f"{address.host}:{address.port}: Could not parse DNS message: {e}")
            return

        # save if replaced by DoQ/DoH
        _id = message.id
        try:
            # handle message
            answer = self.domain_resolver.resolve(message)
        except Exception as _:
            logging.error(f"{address.host}:{address.port}: Could not query Dns message using mode {self.proxy_mode} with error: {traceback.format_exc()}")
            error = True
            answer = Dns.make_response(message, orig_id=_id)
            answer.set_rcode(SERVFAIL)
        else:
            logging.debug(f"{address.host}:{address.port}: Successfully resolved Dns message using mode {self.proxy_mode}. Sending answer to client:\n{answer}")
        # return answer
        self.server.sendto(answer.to_wire(), (address.host, address.port))
        logging.info(f"{address.host}:{address.port}: request resolved")

    def start(self):
        """
        Starts the proxy. After calling the proxy is listening for connections.
        :return:
        """
        if self.proxy_mode == DnsProxyMode.AUTO:
            self.domain_resolver = DnsModeDeterminator(self.timeout).generate_domain_resolver()
        else:
            self.domain_resolver = DomainResolver(dns_mode=self.proxy_mode,
                                                  # TODO: which resolver
                                                  resolver=self.DOT_RESOLVER,
                                                  timeout=self.timeout)

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
            logging.info(f"{address.host}:{address.port}: request received")
            # spawn a new thread that runs the function handle()
            threading.Thread(target=self.handle, args=(message, address)).start()
        logging.info("### Stopped proxy ###")
