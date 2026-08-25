from unittest.mock import MagicMock

import pytest

from exception.ParserException import ParserException
from network.NetworkAddress import NetworkAddress
from network.protocols.Socksv4 import Socksv4


def test_read_socks4_success():
    """Test reading a valid SOCKSv4 request."""
    mock_socket = MagicMock()
    # 0x04 (version), 0x01 (connect), 0x00 0x50 (port 80), 0x08 0x08 0x08 0x08 (ip 8.8.8.8)
    mock_socket.recv.side_effect = [b"\x04", b"\x01", b"\x00\x50", b"\x08\x08\x08\x08"]
    mock_socket.read_until.return_value = b"userid\x00"

    ip, port = Socksv4.read_socks4(mock_socket)
    assert ip == "8.8.8.8"
    assert port == 80


def test_read_socks4_invalid_version():
    """
    Test that reading a SOCKSv4 request raises a ParserException if the SOCKS
    version is invalid (not 4).
    """
    mock_socket = MagicMock()
    mock_socket.recv.return_value = b"\x05"
    with pytest.raises(ParserException, match="Not a SOCKSv4 request"):
        Socksv4.read_socks4(mock_socket)


def test_read_socks4_bind_mode():
    """
    Test that reading a SOCKSv4 request raises a ParserException if the SOCKS
    command is BIND (not CONNECT).
    """
    mock_socket = MagicMock()
    mock_socket.recv.side_effect = [b"\x04", b"\x02"]
    with pytest.raises(ParserException, match="BIND mode not supported"):
        Socksv4.read_socks4(mock_socket)


def test_socks4_request_ipv4():
    """Test encoding a SOCKSv4 request with valid IPv4."""
    addr = NetworkAddress("8.8.8.8", 80)
    req = Socksv4.socks4_request(addr)
    # version (1), command (1), port (2), ip (4), userid (1 - null)
    assert req == b"\x04\x01\x00\x50\x08\x08\x08\x08\x00"


def test_socks4_request_domain():
    """Test encoding a SOCKSv4a request with domain."""
    addr = NetworkAddress("example.com", 80)
    req = Socksv4.socks4_request(addr)
    assert req.startswith(b"\x04\x01\x00\x50")
    assert b"example.com" in req


def test_socks4_ok():
    """
    Test the generation of a SOCKSv4 success response byte representation.
    """
    assert Socksv4.socks4_ok() == b"\00\x5a\xff\xff\xff\xff\xff\xff"
