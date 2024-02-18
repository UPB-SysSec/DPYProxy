import socket

from exception.ParserException import ParserException
from network.NetworkAddress import NetworkAddress
from network.WrappedSocket import WrappedSocket
from util.constants import SOCKSv5_HEADER
from util.Util import is_valid_ipv4_address


class Socksv5:
    """
    Implements SOCKSv5 protocol, only supports no auth
    """

    REQUEST_MODE = b'\x01'
    BIND_MODE = b'\x02'
    UDP_PORT = b'\x03'
    RESERVED_BYTE = b'\x00'
    NO_AUTH = b'\x00'

    @staticmethod
    def read_socks5(connection_socket: WrappedSocket) -> tuple[str, int]:

        # read connection methods
        version = connection_socket.recv(1)
        if version != SOCKSv5_HEADER:
            raise ParserException("Not a SOCKSv4 request")

        number_authentication_methods = int.from_bytes(connection_socket.recv(1))
        if number_authentication_methods == 0:
            connection_socket.send(SOCKSv5_HEADER + b'\xFF')
            raise ParserException("No auth method provided")

        authentication_methods = connection_socket.read(number_authentication_methods)
        if Socksv5.NO_AUTH not in authentication_methods:
            connection_socket.send(SOCKSv5_HEADER + b'\xFF')
            raise ParserException("No auth method not supported by client")

        # always choose no auth
        connection_socket.send(SOCKSv5_HEADER + Socksv5.NO_AUTH)

        # receive destination address
        version = connection_socket.recv(1)
        if version != SOCKSv5_HEADER:
            raise ParserException("Not a SOCKSv5 request")

        mode = connection_socket.recv(1)
        if mode == Socksv5.BIND_MODE:
            raise ParserException("BIND mode not supported")
        if mode == Socksv5.UDP_PORT:
            raise ParserException("UDP mode not supported")
        if mode != Socksv5.REQUEST_MODE:
            raise ParserException(f"Socks mode {mode} not supported")

        if connection_socket.recv(1) != Socksv5.RESERVED_BYTE:
            raise ParserException("Invalid reserved byte")

        host = Socksv5._read_address(connection_socket)

        port = int.from_bytes(connection_socket.read(2), byteorder='big')
        if not 0 <= port <= 65535:
            raise ParserException(f"Invalid port {port}")

        return host, port

    @staticmethod
    def _read_address(connection_socket: WrappedSocket) -> str:
        address_type = connection_socket.recv(1)
        if address_type == b'\x01':
            # ipv4
            host = '.'.join(f'{c}' for c in connection_socket.recv(4))
        elif address_type == b'\x04':
            # ipv6
            host = ':'.join(f'{c}' for c in connection_socket.recv(16))
        elif address_type == b'\x03':
            # domain
            length = int.from_bytes(connection_socket.recv(1), byteorder='big')
            host = connection_socket.read(length).decode('utf-8')
        else:
            raise ParserException(f"Address type {address_type} not supported")
        return host

    @staticmethod
    def socks5_auth_methods() -> bytes:
        return SOCKSv5_HEADER + b'\x01' + Socksv5.NO_AUTH

    @staticmethod
    def socks5_request(server_address: NetworkAddress):
        if not is_valid_ipv4_address(server_address.host):
            # Socksv5 domain encoding
            return SOCKSv4_HEADER + b'\x01' + server_address.port.to_bytes(2, byteorder='big') + \
                    "0.0.0.1".encode("'utf-8") + b'\x00' + server_address.host.encode('utf-8') + b'\x00'
        else:
            # Socksv4 ip encoding
            return SOCKSv4_HEADER + b'\x01' + server_address.port.to_bytes(2, byteorder='big') + \
               bytes([int(i) for i in server_address.host.split('.')]) + b'\x00'

    @staticmethod
    def socks5_ok(connection_socket: WrappedSocket) -> bytes:
        host_ip, host_port = connection_socket.socket.getsockname()
        host_address = socket.inet_aton(host_ip)
        return SOCKSv5_HEADER + '\x00' + Socksv5.RESERVED_BYTE + host_address + host_port.to_bytes(2, byteorder='big')