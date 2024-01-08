from exception.ParserException import ParserException
from network.NetworkAddress import NetworkAddress
from network.WrappedSocket import WrappedSocket
from util.constants import SOCKSv4_HEADER


class Socks:

    REQUEST_MODE = 0x01
    BIND_MODE = 0x02

    @staticmethod
    def read_socks4(connection_socket: WrappedSocket) -> tuple[str, int]:

        version = connection_socket.recv(1)
        if version != SOCKSv4_HEADER:
            raise ParserException("Not a SOCKSv4 request")

        mode = connection_socket.recv(1)
        if mode == Socks.BIND_MODE:
            raise ParserException("BIND mode not supported")
        if mode != Socks.REQUEST_MODE:
            raise ParserException(f"Socks mode {mode} not supported")

        port = int.from_bytes(connection_socket.recv(2), byteorder='big')
        if not 0 <= port <= 65535:
            raise ParserException(f"Invalid port {port}")

        # str ip from bytes
        ip = '.'.join(f'{c}' for c in connection_socket.recv(4))

        # ignore user_id but parse bytes
        connection_socket.read_until([b'\x00'])

        return ip, port

    @staticmethod
    def socks4_request(server_address: NetworkAddress):
        return SOCKSv4_HEADER + b'\x01' + server_address.port.to_bytes(2, byteorder='big') + \
               bytes([int(i) for i in server_address.host.split('.')]) + b'\x00'

    @staticmethod
    def socks4_ok() -> bytes:
        return SOCKSv4_HEADER + b'\00\x5a\xFF\xFF\xFF\xFF\xFF\xFF'
