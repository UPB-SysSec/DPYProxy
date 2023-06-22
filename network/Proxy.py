import logging
import socket
import threading

import dns

from network.WrappedSocket import WrappedSocket
from exception.ParserException import ParserException
from enumerators.ProxyMode import ProxyMode
from util.Util import is_valid_ipv4_address
from util.constants import TLS_1_0_HEADER, TLS_1_2_HEADER, TLS_1_1_HEADER, HTTP_200_RESPONSE


class Proxy:
    """
    Proxy server
    """

    def __init__(self, timeout: int = 120, port: int = 4433, record_frag: bool = False, tcp_frag: bool = False,
                 frag_size: int = 20, dot: bool = False, dot_ip: str = "8.8.4.4", proxy_mode: ProxyMode = ProxyMode.ALL,
                 forward_proxy_address: str = None, forward_proxy_port: int = None,
                 forward_proxy_mode: ProxyMode = ProxyMode.SNI, forward_proxy_resolve_address: bool = False):
        # timeout for socket reads and message reception
        self.timeout = timeout
        # own port
        self.port = port
        # record fragmentation settings
        self.record_frag = record_frag
        self.tcp_frag = tcp_frag
        self.frag_size = frag_size
        # whether to use dot for domain resolution
        self.dot = dot
        self.dot_ip = dot_ip
        # own proxy mode
        self.proxy_mode = proxy_mode
        # settings for another proxy to contact further down the line
        self.forward_proxy_address = forward_proxy_address
        self.forward_proxy_port = forward_proxy_port
        self.forward_proxy_mode = forward_proxy_mode
        self.forward_proxy_resolve_address = forward_proxy_resolve_address
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def resolve_domain(self, domain: str) -> str:
        """
        Resolves the given domain to an ip address.
        :param domain: domain name to resolve
        :return: One ip address for the domain or None
        """
        if not self.dot:
            return socket.gethostbyname(domain)
        else:
            # TODO: doh/doq
            domain = dns.name.from_text(domain)
            if not domain.is_absolute():
                domain = domain.concatenate(dns.name.root)

            query = dns.message.make_query(domain, dns.rdatatype.A)
            query.flags |= dns.flags.AD
            query.find_rrset(query.additional, dns.name.root, 65535,
                             dns.rdatatype.OPT, create=True, force_unique=True)
            response = dns.query.tls(query, self.dot_ip)

            if response.rcode() != dns.rcode.NOERROR:
                return None

            # filter ipv4 answer
            ips = []
            for record in response.answer:
                if record.rdtype == dns.rdatatype.A:
                    for item in record.items:
                        ips.append(str(item.address))
            if len(ips) > 0:
                return ips[0]
            else:
                # read CNAME hostnames from answer
                for record in response.answer:
                    if record.rdtype == dns.rdatatype.CNAME:
                        for item in record.items:
                            return self.resolve_domain(str(item.target))
                return None

    # TODO: replace with correct forwarding that cancels both sockets if one does
    def forward(self, from_socket: WrappedSocket, to_socket: WrappedSocket, record_frag=False):
        """
        Forwards data between two sockets with optional record fragmentation. Falls back to forwarding if no TLS records
        can be parsed from the connection anymore.
        :param to_socket: Socket to receive data from.
        :param from_socket: Socket to forward data to.
        :param record_frag: Whether to fragment handshake records
        :return: None
        """
        try:
            while True:
                if not record_frag:
                    if not record_frag:
                        data = from_socket.recv(4096)
                        if not data:
                            try:
                                to_socket.close()
                            except:
                                pass
                        else:
                            to_socket.send(data)
                else:
                    try:
                        record_header = from_socket.peek(5)
                    except:
                        logging.debug("Could not read record_header bytes")
                        record_frag = False
                        continue
                    base_header = record_header[:3]
                    record_len = int.from_bytes(record_header[3:], byteorder='big')
                    is_tls = base_header == TLS_1_0_HEADER or base_header == TLS_1_1_HEADER \
                             or base_header == TLS_1_2_HEADER
                    if not is_tls:
                        logging.debug(f"Not a TLS handshake record header: {record_header}")
                        # did not receive tls record
                        record_frag = False
                        continue
                    try:
                        record = from_socket.read(5 + record_len)[5:]
                    except:
                        logging.debug(f"Could not read {record_len} record bytes")
                        record_frag = False
                        continue
                    fragments = [record[i:i + self.frag_size] for i in range(0, record_len, self.frag_size)]
                    fragmented_message = b''
                    for fragment in fragments:
                        # construct header
                        fragmented_message += base_header + int.to_bytes(len(fragment), byteorder='big', length=2)
                        fragmented_message += fragment
                    to_socket.send(fragmented_message)
        except BrokenPipeError:
            logging.info(f"Forwarding from {from_socket.socket.getpeername()} to {to_socket.socket.getpeername()} "
                         f"broken.")

    def get_destination_address(self, ssocket: WrappedSocket) -> (str, int, bool):
        """
        Reads a proxy destination address and returns the host and port of the destination.
        :return: Host and port of the destination server.
        """
        proxy_mode = self.proxy_mode
        # dynamically determine proxy mode
        if proxy_mode == ProxyMode.ALL:
            header = ssocket.peek(16)
            if header.startswith(b'GET ') or header.startswith(b'POST '):
                logging.info('HTTP Proxy Request')
                proxy_mode = ProxyMode.HTTP
            elif header.startswith(b'CONNECT'):
                logging.info('HTTPS Proxy Request')
                proxy_mode = ProxyMode.HTTPS
            elif header.startswith(TLS_1_0_HEADER) or header.startswith(TLS_1_1_HEADER) \
                    or header.startswith(TLS_1_2_HEADER):
                logging.info('SNI Proxy Request')
                proxy_mode = ProxyMode.SNI
            else:
                raise ParserException(f"Could not determine message type of message {header}")

        if proxy_mode == ProxyMode.HTTP:
            host, port, needs_proxy_message = ssocket.read_http_get(), 80, False
            logging.debug(f"Read host {host} and port {port} from HTTP GET")
        elif proxy_mode == ProxyMode.HTTPS:
            host, port = ssocket.read_http_connect()
            needs_proxy_message = True
            # answer with 200 OK
            ssocket.send(HTTP_200_RESPONSE)
            logging.debug(f"Read host {host} and port {port} from HTTP connect")
        elif proxy_mode == ProxyMode.SNI:
            host, port, needs_proxy_message = ssocket.read_sni(), 443, True
            logging.debug(f"Read host {host} and port {port} from SNI")
        else:
            raise ParserException("Unknown proxy type")
        return host, port, needs_proxy_message

    def handle(self, client_socket: WrappedSocket):
        """
        Handles the connection to a single client.
        :param client_socket: The socket of the client connection.
        :return: None
        """
        logging.debug("handling request")
        # determine destination address
        try:
            host, port, needs_proxy_message = self.get_destination_address(client_socket)
        except ParserException as e:
            logging.warning(f"Could not parse initial proxy message with {e}. Stopping!")
            return

        # resolve domain if forward host wants it, or we do not have a forward host
        if not is_valid_ipv4_address(host) and \
                (self.forward_proxy_resolve_address or self.forward_proxy_address is None):
            _host = host
            host = self.resolve_domain(host)
            logging.debug(f"Resolved {host} from {_host}")

        # set correct target
        if self.forward_proxy_address is None:
            target_host = host
            target_port = port
        else:
            target_host = self.forward_proxy_address
            target_port = self.forward_proxy_port
            logging.debug(f"Using forward proxy. Changing {host}->{target_host} and {port}->{target_port}")

        # open socket to server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((target_host, target_port))
        if self.tcp_frag and self.record_frag:
            # align record and tcp fragment size
            server_socket = WrappedSocket(self.timeout, server_socket, self.frag_size + 5)
        elif self.tcp_frag:
            server_socket = WrappedSocket(self.timeout, server_socket, self.frag_size)
        else:
            server_socket = WrappedSocket(self.timeout, server_socket)
        logging.debug(f"Connected to {target_host}:{target_port}")

        # send proxy messages if necessary
        # TODO: also support proxy authentication?
        if self.forward_proxy_address is not None and self.forward_proxy_mode == ProxyMode.HTTPS \
                and needs_proxy_message:
            server_socket.send(f'CONNECT {host}:{port} HTTP/1.1\nHost: {host}:{port}\n\n'
                               .encode('ASCII'))
            logging.debug("Send HTTP CONNECT to forward proxy")
            # receive HTTP 200 OK
            answer = server_socket.recv(4096)
            if not answer.startswith(HTTP_200_RESPONSE):
                logging.debug("Forward proxy rejected the connection")

        # start proxying
        threading.Thread(target=self.forward, args=(client_socket, server_socket, self.record_frag)).start()
        threading.Thread(target=self.forward, args=(server_socket, client_socket)).start()

    def start(self):
        """
        Starts the proxy. After calling the proxy is listening for connections.
        :return:
        """
        # opening server socket
        self.server.bind(("0.0.0.0", self.port))
        self.server.listen()
        print(f"### Started {self.proxy_mode} proxy on {self.port} ###")
        while True:  # listen for incoming connections
            client_socket, address = self.server.accept()
            client_socket = WrappedSocket(self.timeout, client_socket)
            logging.debug(f"request from the ip {address[0]}")
            # spawn a new thread that run the function handle()
            threading.Thread(target=self.handle, args=(client_socket,)).start()