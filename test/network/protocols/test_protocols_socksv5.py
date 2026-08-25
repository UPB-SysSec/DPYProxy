import socket
from unittest.mock import MagicMock

import pytest

from exception.ParserException import ParserException
from network.NetworkAddress import NetworkAddress
from network.protocols.Socksv5 import Socksv5


def test_read_socks5_success_ipv4():
    """
    Test that reading a valid SOCKSv5 connection request (IPv4 target) successfully
    negotiates authentication and parses the target IP and port.
    """
    mock_socket = MagicMock()

    # Each time read_socks5 is called with mock_socket,
    # the following sequence of recv and read calls will be made:
    # 1. recv(1) -> 0x05 (version)
    # 2. recv(1) -> 0x01 (num auth methods)
    # 3. read(1) -> 0x00 (auth methods)
    # 4. recv(1) -> 0x05 (version in request)
    # 5. recv(1) -> 0x01 (connect mode)
    # 6. recv(1) -> 0x00 (reserved)
    # 7. recv(1) -> 0x01 (address type ipv4)
    # 8. read(4) -> 8.8.8.8
    # 9. read(2) -> port 80

    mock_socket.recv.side_effect = [b"\x05", b"\x01", b"\x05", b"\x01", b"\x00", b"\x01"]
    mock_socket.read.side_effect = [b"\x00", b"\x08\x08\x08\x08", b"\x00\x50"]

    host, port = Socksv5.read_socks5(mock_socket)
    assert host == "8.8.8.8"
    assert port == 80


def test_read_socks5_invalid_version():
    """
    Test that reading a SOCKSv5 request raises a ParserException if the SOCKS
    version byte is invalid (not 5).
    """
    mock_socket = MagicMock()
    mock_socket.recv.return_value = b"\x04"
    with pytest.raises(ParserException, match="Not a SOCKSv5 request"):
        Socksv5.read_socks5(mock_socket)


def test_socks5_auth_methods():
    """
    Test the generation of SOCKSv5 supported authentication methods bytes.
    """
    assert Socksv5.socks5_auth_methods() == b"\x05\x01\x00"


def test_socks5_request_ipv4():
    """
    Test encoding a SOCKSv5 connection request specifying an IPv4 address.
    """
    addr = NetworkAddress("8.8.8.8", 80)
    req = Socksv5.socks5_request(addr)
    # version(5), connect(1), reserved(0), ipv4(1), ip(4 bytes), port(2 bytes)
    assert req == b"\x05\x01\x00\x01\x08\x08\x08\x08\x00\x50"


def test_socks5_request_domain():
    """
    Test encoding a SOCKSv5 connection request specifying a domain name.
    """
    addr = NetworkAddress("example.com", 80)
    req = Socksv5.socks5_request(addr)
    assert req.startswith(b"\x05\x01\x00\x03")
    assert b"example.com" in req


def test_socks5_ok():
    """
    Test the generation of SOCKSv5 success response byte representation based
    on the current socket details.
    """
    mock_socket = MagicMock()
    mock_socket.socket.getsockname.return_value = ("127.0.0.1", 1080)
    resp = Socksv5.socks5_ok(mock_socket)
    assert resp == b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + (1080).to_bytes(2, "big")
