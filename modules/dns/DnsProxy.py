import logging
import select
import socket
import threading
import traceback

from dns.message import Message, make_query
from dns.rcode import SERVFAIL

from enumerators.DnsProxyMode import DnsProxyMode
from exception.DnsException import DnsException
from modules.dns.DnsModeDeterminator import DnsModeDeterminator
from modules.dns.DnsResolver import DnsResolver
from network.DomainResolver import DomainResolver
from network.NetworkAddress import NetworkAddress
from network.protocols.Dns import Dns
from network.tcp.WrappedTcpSocket import WrappedTcpSocket


class DnsProxy:
    """
    Proxy server
    """

    def __init__(self, address: NetworkAddress,
                 timeout: int,
                 proxy_mode: DnsProxyMode,
                 dns_resolver_address: NetworkAddress,
                 censored_domain: str,
                 censored_domain_ip_ranges: list[str],
                 add_sni: bool):
                # timeout for socket reads and message reception
                self.timeout = timeout
                self.address = address
                self.resolver_address = dns_resolver_address
                self.censored_domain = censored_domain
                self.censored_domain_ip_ranges = censored_domain_ip_ranges
                self.proxy_mode = proxy_mode
                self.add_sni = add_sni

                # initialize UDP and TCP server sockets
                self.udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.udp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.udp_server.settimeout(timeout)
                self.tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.udp_server.settimeout(timeout)
                self.continue_processing = True
                # initialized in start()
                self.domain_resolver: DomainResolver|None = None

    def handle_udp(self, message: bytes, address: NetworkAddress):
        answer = self.resolve_message(message, address)
        self.udp_server.sendto(answer.to_wire(), (address.host, address.port))
        logging.info(f"{address.host}:{address.port}: request resolved")

    def handle_tcp(self, client_socket: WrappedTcpSocket, address: NetworkAddress):
        try:
            # read 2-byte length field
            _len = int.from_bytes(client_socket.read(2), byteorder='big')
            # read following message
            request = client_socket.read(_len)
        except Exception as e:
            logging.error(f"Could not receive client DNS request with exception: {e}")
            return
        else:
            answer = self.resolve_message(request=request, address=address)
            if answer is not None:
                client_socket.send(answer.to_wire(prepend_length=True))


    def resolve_message(self, request: bytes, address: NetworkAddress) -> Message | None:
        """
        Resolves the given DNS request bytes at the provider configured on the domain_resolver. Returns an Error DNS
        message on resolution errors and None when the DNS request in unparseable.
        """
        # receive message from client
        try:
            request = Dns.read_dns(request)
            logging.debug(f"{address.host}:{address.port}: parsed dns message:\n{request}")
        except DnsException as e:
            logging.error(f"{address.host}:{address.port}: Could not parse DNS message: {e}")
            return None

        # save if replaced by DoQ/DoH
        _id = request.id
        try:
            # handle message
            answer = self.domain_resolver.resolve(request)
        except Exception as _:
            logging.error(
                f"{address.host}:{address.port}: Could not query Dns message using mode {self.proxy_mode} with error: {traceback.format_exc()}")
            answer = Dns.make_response(request, orig_id=_id)
            answer.set_rcode(SERVFAIL)
        else:
            logging.debug(
                f"{address.host}:{address.port}: Successfully resolved Dns message using mode {self.proxy_mode}. Sending answer to client:\n{answer}")
        return answer

    def generate_domain_resolver(self):
        """
        Generator that yields a new DomainResolver based on the CLI configuration.
        """
        if self.proxy_mode == DnsProxyMode.AUTO:
            _gen = DnsModeDeterminator(self.timeout, self.censored_domain,
                                self.censored_domain_ip_ranges).generate_working_resolver()
            yield from _gen

        elif self.resolver_address.host is None:
            _gen = DnsModeDeterminator(self.timeout, self.censored_domain,
                                self.censored_domain_ip_ranges).generate_working_resolver(self.proxy_mode)
            yield from _gen

        elif self.resolver_address.port is not None:
            logging.info(
                f"mode {self.proxy_mode} and resolver {self.resolver_address.host} specified. Setting standard port {self.proxy_mode.default_port()}.")
            # mode and resolver specified, set standard port accordingly
            yield DomainResolver(dns_mode=self.proxy_mode,
                                 resolver=NetworkAddress(self.resolver_address.host,
                                                         self.proxy_mode.default_port()),
                                 timeout=self.timeout,
                                 hostname="",
                                 add_sni=self.add_sni)
        else:
            logging.info(
                f"mode {self.proxy_mode} and resolver {self.resolver_address.host}:{self.resolver_address.port} specified. Using these values.")
            # mode, resolver, and port specified
            yield DomainResolver(dns_mode=self.proxy_mode,
                                 resolver=self.resolver_address,
                                 timeout=self.timeout,
                                 hostname="",
                                 add_sni=self.add_sni)



    def configure(self):
        """
        Determines a working domain resolver / circumvention method based on the CLI configuration.
        """
        logging.info("Determining working circumvention method / resolver!")
        found_working = False
        domain_resolver_generator = self.generate_domain_resolver()

        while not found_working:
            # determine next possible resolver
            try:
                dns_resolver: DnsResolver = next(domain_resolver_generator)
                domain_resolver: DomainResolver = DomainResolver(dns_mode=dns_resolver.mode,
                                                                 resolver=dns_resolver.address,
                                                                 timeout=self.timeout,
                                                                 hostname=dns_resolver.hostname,
                                                                 add_sni=self.add_sni,
                                                                 path=dns_resolver.path)
            except StopIteration:
                raise DnsException("No working circumvention method found according to specification in CLI.")

            # determine if it is working
            logging.info(f"Found working circumvention method / resolver {domain_resolver}! Checking of consistently reachable!")
            found_working  = domain_resolver.works(message=make_query(self.censored_domain, "A"))
            if not found_working:
                logging.info(f"{domain_resolver} not consistently reachable, attempting to generate new resolver.")
            else:
                logging.info(f"{domain_resolver} consistently reachable, keeping!")
                self.domain_resolver = domain_resolver
                self.proxy_mode = self.domain_resolver.dns_mode



    def start(self):
        """
        Starts the proxy. After calling the proxy, listens for connections.
        """
        try:
            # determine circumvention method
            self.configure()
        except DnsException as e:
            logging.error(f"{e}")
        else:
            # start tcp and udp DNS server
            threading.Thread(target=self.start_udp_server).start()
            threading.Thread(target=self.start_tcp_server).start()


    def start_udp_server(self):
        """
        Runs a UDP DNS server.
        """
        # opening server socket
        self.udp_server.bind((self.address.host, self.address.port))
        print(f"### Started UDP DNS server on {self.address.host}:{self.address.port} ###")

        while self.continue_processing:
            readable, _, _ = select.select([self.udp_server], [], [], 1)
            if not readable:
                continue
            # listen for incoming connections
            message, address = self.udp_server.recvfrom(Dns.DNS_MAX_SIZE * 4)
            address = NetworkAddress(address[0], address[1])
            logging.info(f"{address.host}:{address.port}: request received over UDP")
            # spawn a new thread that runs the function handle()
            threading.Thread(target=self.handle_udp, args=(message, address)).start()
        logging.info("### Stopped UDP DNS server ###")

    def start_tcp_server(self):
        """
        Runs a TCP DNS server.
        """
        # opening server socket
        self.tcp_server.bind((self.address.host, self.address.port))
        self.tcp_server.listen()
        print(f"### Started TCP DNS server on {self.address.host}:{self.address.port} ###")

        while self.continue_processing:
            readable, _, _ = select.select([self.tcp_server], [], [], 1)
            if not readable:
                continue
            # listen for incoming connections
            client_socket, address = self.tcp_server.accept()
            address = NetworkAddress(address[0], address[1])
            client_socket = WrappedTcpSocket(self.timeout, client_socket)
            logging.info(f"{address.host}:{address.port}: DNS request received over TCP")
            # spawn a new thread that runs the function handle()
            threading.Thread(target=self.handle_tcp, args=(client_socket, address)).start()
        logging.info("### Stopped TCP DNS server ###")