from exception.ParserException import ParserException
from network.NetworkAddress import NetworkAddress
from network.WrappedSocket import WrappedSocket
from util.constants import SOCKSv4_HEADER
from util.Util import is_valid_ipv4_address


class Socksv4:
    """
    Implements SOCKSv4a protocol
    """

    REQUEST_MODE = b'\01'
    BIND_MODE = b'\02'

    @staticmethod
    def read_socks4(connection_socket: WrappedSocket) -> tuple[str, int]:

        version = connection_socket.recv(1)
        if version != SOCKSv4_HEADER:
            raise ParserException("Not a SOCKSv4 request")

        mode = connection_socket.recv(1)
        if mode == Socksv4.BIND_MODE:
            raise ParserException("BIND mode not supported")
        if mode != Socksv4.REQUEST_MODE:
            raise ParserException(f"Socks mode {mode} not supported")

        port = int.from_bytes(connection_socket.recv(2), byteorder='big')
        if not 0 <= port <= 65535:
            raise ParserException(f"Invalid port {port}")

        # str ip from bytes
        ip = '.'.join(f'{c}' for c in connection_socket.recv(4))

        # ignore user_id but parse bytes until null byte
        connection_socket.read_until([b'\x00'])

        # socksv4a allows for domain/ip? behind user id
        if ip.startswith("0.0.0."):
            ip = connection_socket.read_until([b'\x00'])[:-1].decode("utf-8")

        return ip, port

    @staticmethod
    def socks4_request(server_address: NetworkAddress):
        if not is_valid_ipv4_address(server_address.host):
            # Socksv4a domain encoding
            return SOCKSv4_HEADER + b'\x01' + server_address.port.to_bytes(2, byteorder='big') + \
                    "0.0.0.1".encode("'utf-8") + b'\x00' + server_address.host.encode('utf-8') + b'\x00'
        else:
            # Socksv4 ip encoding
            return SOCKSv4_HEADER + b'\x01' + server_address.port.to_bytes(2, byteorder='big') + \
               bytes([int(i) for i in server_address.host.split('.')]) + b'\x00'

    @staticmethod
    def socks4_ok() -> bytes:
        return b'\00\x5a\xFF\xFF\xFF\xFF\xFF\xFF'
