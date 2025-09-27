import socket
from typing import Optional

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
    USERPASS = b'\x02'

    @staticmethod
    def read_socks5(connection_socket: WrappedSocket) -> tuple[str, int]:

        # read connection methods
        version = connection_socket.recv(1)
        if version != SOCKSv5_HEADER:
            raise ParserException("Not a SOCKSv5 request")

        number_authentication_methods = int.from_bytes(connection_socket.recv(1), byteorder='big')
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
            host = '.'.join(f'{c}' for c in connection_socket.read(4))
        elif address_type == b'\x04':
            # ipv6
            host = ':'.join(f'{c}' for c in connection_socket.read(16))
        elif address_type == b'\x03':
            # domain
            length = int.from_bytes(connection_socket.read(1), byteorder='big')
            host = connection_socket.read(length).decode('utf-8')
        else:
            raise ParserException(f"Address type {address_type} not supported")
        return host

    @staticmethod
    def socks5_auth_methods(username: Optional[str] = None, password: Optional[str] = None, auth_policy: str = 'auto') -> bytes:
        """
        Returns SOCKSv5 authentication method selection message.
        In 'auto' mode with credentials, we propose [USERPASS, NO_AUTH] and accept server's choice.
        This allows fallback to no auth if the server doesn't support userpass, which is intentional.
        """
        policy = (auth_policy or 'auto').lower()
        methods = []
        has_creds = username is not None and password is not None

        if policy == 'no_auth':
            methods = [Socksv5.NO_AUTH]
        elif policy == 'userpass':
            if not has_creds:
                raise ParserException("SOCKSv5 userpass policy selected but username/password not provided")
            methods = [Socksv5.USERPASS]
        elif policy == 'auto':
            if has_creds:
                methods = [Socksv5.USERPASS, Socksv5.NO_AUTH]
            else:
                methods = [Socksv5.NO_AUTH]
        else:
            raise ParserException(f"Unknown SOCKSv5 auth policy: {auth_policy}")

        return SOCKSv5_HEADER + len(methods).to_bytes(1, byteorder='big') + b''.join(methods)

    @staticmethod
    def socks5_auth_username_password(username: str, password: str) -> bytes:
        """
        RFC 1929 username/password authentication sub-negotiation.
        """
        username_bytes = username.encode('utf-8')
        password_bytes = password.encode('utf-8')
        if len(username_bytes) > 255 or len(password_bytes) > 255:
            raise ParserException("Username/password too long for SOCKS5 (max 255)")
        return b'\x01' + len(username_bytes).to_bytes(1, byteorder='big') + username_bytes \
               + len(password_bytes).to_bytes(1, byteorder='big') + password_bytes

    @staticmethod
    def socks5_request(server_address: NetworkAddress):
        if not is_valid_ipv4_address(server_address.host):
            domain = server_address.host.encode('utf-8')
            address = b'\x03' + len(domain).to_bytes(1, byteorder='big') + domain
        else:
            address = b'\x01' + socket.inet_aton(server_address.host)
        return (SOCKSv5_HEADER + b'\x01' + Socksv5.RESERVED_BYTE + address
                + server_address.port.to_bytes(2, byteorder='big'))

    @staticmethod
    def socks5_ok(connection_socket: WrappedSocket) -> bytes:
        host_ip, host_port = connection_socket.socket.getsockname()
        host_address = b'\x01' + socket.inet_aton(host_ip)
        return SOCKSv5_HEADER + b'\x00' + Socksv5.RESERVED_BYTE + host_address + host_port.to_bytes(2, byteorder='big')
