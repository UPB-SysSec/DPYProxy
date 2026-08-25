from urllib.parse import urlsplit

from enumerators.HttpMethod import HttpMethod
from exception.ParserException import ParserException
from network.NetworkAddress import NetworkAddress
from network.tcp.WrappedTcpSocket import WrappedTcpSocket
from util.Util import is_valid_ipv6_address


class Http:
    """
    Implements methods to parse HTTP messages.
    """

    @staticmethod
    def is_valid_http(wrapped_socket: WrappedTcpSocket) -> bool:
        try:
            Http._parse_http_method(wrapped_socket, HttpMethod.all(), True)
            return True
        except ParserException:
            return False

    @staticmethod
    def _parse_http_method(wrapped_socket: WrappedTcpSocket, methods: list[str], peek: bool = False) -> (str, int, str):
        """
        Reads the first line of a http method to parse the domain from it.
        :return: host and port in the method, defaults to port 80 if no port found
        """
        try:
            # read complete message
            message = wrapped_socket.read_until([b"\n\n", b"\r\n\r\n"], 500, peek).decode("ASCII")
            # extract first line, assume that \r\n are at least used coherently in the message
            if "\r\n" in message:
                first_line = message.split("\r\n")[0]
            else:
                first_line = message.split("\n")[0]
        except UnicodeDecodeError as e:
            raise ParserException(f"Could not decode ASCII in first line of HTTP request with exception {e}")
        # check for any method
        parsed_method = False
        for method in methods:
            if first_line.upper().startswith(f"{method.upper()} "):
                parsed_method = True
        if not parsed_method:
            raise ParserException(f"Not a {methods} request")
        if first_line.count(" ") not in [1, 2]:
            raise ParserException("Not a valid HTTP request, could not determine target URI")
        if first_line.count(" ") == 1:
            # HTTP/0.9
            _, uri = first_line.split(" ")
            version = "HTTP/0.9"
        else:
            _, uri, version = first_line.split(" ")
        if version.upper() != "HTTP/1.1" and version.upper() != "HTTP/1.0" and version.upper() != "HTTP/0.9":
            raise ParserException("Not a valid HTTP request, only HTTP/0.9, HTTP/1.0, and HTTP/1.1 supported")
        host, _, port = Http.parse_uri(uri)
        return host, port, version

    @staticmethod
    def read_http_get(wrapped_socket: WrappedTcpSocket) -> (str, int, str):
        """
        Reads the first line of a http get request.
        :return: host, port, and version from the http get request.
        """
        return Http._parse_http_method(wrapped_socket, ["GET"], True)

    @staticmethod
    def read_http_connect(wrapped_socket: WrappedTcpSocket) -> (str, int, str):
        """
        Reads the first line of a http connect request.
        :return: host, port, and http version from the http connect request.
        """
        return Http._parse_http_method(wrapped_socket, ["CONNECT"], False)

    @staticmethod
    def parse_uri(input_string: str, default_port: int = 80) -> (str, str, int):
        """
        Parses a URI into its host, path and port components.
        Parameters are currently not parsed.
        :param uri: uri to parse
        :return: host, path, port
        """
        # if IP address, enforce a fake scheme so urlsplit parses the netloc reliably
        if "//" not in input_string:
            input_string = f"//{input_string}"

        parsed = urlsplit(input_string)

        host = parsed.hostname
        port = parsed.port if parsed.port else default_port
        path = parsed.path if parsed.path else "/"

        return host, path, port

    @staticmethod
    def connect_message(server_address: NetworkAddress, version: str) -> bytes:
        host_display = f"[{server_address.host}]" if is_valid_ipv6_address(server_address.host) else server_address.host
        return (
            f"CONNECT {host_display}:{server_address.port} {version}\n"
            f"Host: {host_display}:{server_address.port}\n\n".encode("ASCII")
        )

    @staticmethod
    def http_200_ok(version: str) -> bytes:
        return f"{version} 200 OK\n\n".encode("ASCII")
