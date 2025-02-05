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

    def __init__(self, address: NetworkAddress,
                 timeout: int,
                 proxy_mode: DnsProxyMode,
                 dns_resolver_address: NetworkAddress):
                # timeout for socket reads and message reception
                self.timeout = timeout
                self.address = address
                self.resolver_address = dns_resolver_address
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
        """
        # TODO: implement failsafe mechanism. I.e., require more than one connection to success, also for user provided values.
        try:
            if self.proxy_mode == DnsProxyMode.AUTO:
                # determine mode and resolver automatically
                logging.info("AUTO mode set. Determining mode, and resolver automatically.")
                self.domain_resolver = DnsModeDeterminator(self.timeout).generate_domain_resolver()
            elif self.resolver_address.host is None:
                # determine resolver for selected mode automatically
                logging.info(f"mode {self.proxy_mode} specified. Determining resolver automatically.")
                self.domain_resolver = DnsModeDeterminator(self.timeout).generate_domain_resolver(self.proxy_mode)
            elif self.resolver_address.port is not None:
                logging.info(f"mode {self.proxy_mode} and resolver {self.resolver_address.host} specified. Setting standard port {self.proxy_mode.default_port()}.")
                # mode and resolver specified, set standard port accordingly
                self.domain_resolver = DomainResolver(dns_mode=self.proxy_mode,
                                                      resolver=NetworkAddress(self.resolver_address.host, self.proxy_mode.default_port()),
                                                      timeout=self.timeout)
            else:
                # mode, resolver, and port specified
                logging.info(f"mode {self.proxy_mode} and resolver {self.resolver_address.host}:{self.resolver_address.port} specified. Using these values.")
                self.domain_resolver = DomainResolver(dns_mode=self.proxy_mode,
                                                      resolver=self.resolver_address,
                                                      timeout=self.timeout)
        except Exception as e:
            logging.error(f"Could not create DomainResolver with exception: {e}")
            return

        # opening server socket
        self.server.bind((self.address.host, self.address.port))
        # TODO: run on TCP and UDP
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
