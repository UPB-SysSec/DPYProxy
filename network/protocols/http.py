from exception.ParserException import ParserException
from network.NetworkAddress import NetworkAddress
from network.WrappedSocket import WrappedSocket


# TODO: HTTP/2 support
class Http:
    """
    Implements methods to parse HTTP messages.
    """

    @staticmethod
    def _parse_http_method(wrapped_socket: WrappedSocket, method: str, peek: bool = False) -> (str, int, str):
        """
        Reads the first line of a http method to parse the domain from it.
        :return: host and port in the method, defaults to port 80 if no port found
        """
        method = method.upper()
        try:
            # read complete message
            message = wrapped_socket.read_until([b'\n\n', b'\r\n\r\n'], 500, peek).decode('ASCII')
            # extract first line, assume that \r\n are at least used coherently in the message
            if "\r\n" in message:
                first_line = message.split("\r\n")[0]
            else:
                first_line = message.split("\n")[0]
        except UnicodeDecodeError as e:
            raise ParserException(f"Could not decode ASCII in first line of HTTP {method} request with exception {e}")
        if not first_line.upper().startswith(f'{method} '):
            raise ParserException(f"Not a {method} request")
        if first_line.count(" ") != 2:
            raise ParserException(f"Not a valid {method} request, could not determine target URI")
        _, uri, version = first_line.split(" ")
        if version.upper() != "HTTP/1.1" and version.upper() != "HTTP/1.0" and version.upper() != "HTTP/0.9":
            raise ParserException(f"Not a valid {method} request, only HTTP/0.9 HTTP/1.0, and HTTP/1.1 supported")
        host, _, port = Http.parse_uri(uri)
        return host, port, version

    @staticmethod
    def read_http_get(wrapped_socket: WrappedSocket) -> (str, int, str):
        """
        Reads the first line of a http get request.
        :return: host, port, and version from the http get request.
        """
        return Http._parse_http_method(wrapped_socket, "GET", True)

    @staticmethod
    def read_http_connect(wrapped_socket: WrappedSocket) -> (str, int, str):
        """
        Reads the first line of a http connect request.
        :return: host, port, and http version from the http connect request.
        """
        return Http._parse_http_method(wrapped_socket, "CONNECT", False)

    @staticmethod
    def parse_uri(uri: str) -> (str, str, int):
        """
        Parses a URI into its host, path and port components.
        Parameters are currently not parsed.
        :param uri: uri to parse
        :return: host, path, port
        """
        if "://" in uri:
            # remove protocol prefix if present
            uri = uri.split("://")[1]

        if "/" in uri:
            # split host and path
            uri, path = uri.split("/", 1)
            path = "/" + path
        else:
            path = "/"

        if ":" in uri:
            # split host and port
            uri, port = uri.split(":")
            port = int(port)
        else:
            port = 80

        return uri, path, port

    @staticmethod
    def connect_message(server_address: NetworkAddress, version: str) -> bytes:
        return (f'CONNECT {server_address.host}:{server_address.port} {version}\n'
                f'Host: {server_address.host}:{server_address.port}\n\n'
                .encode('ASCII'))

    @staticmethod
    def http_200_ok(version: str) -> bytes:
        return f'{version} 200 OK\n\n'.encode("ASCII")
