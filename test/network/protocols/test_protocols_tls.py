from unittest.mock import MagicMock

import pytest

from exception.ParserException import ParserException
from network.protocols.Tls import Tls
from util.constants import TLS_1_2_HEADER


def test_read_tls_record_success():
    """Test reading a simple TLS record."""
    mock_socket = MagicMock()
    # 5 bytes header: TLS_1_2_HEADER (3), length (2)
    mock_socket.read.side_effect = [TLS_1_2_HEADER + b"\x00\x05", b"hello"]

    record = Tls._read_tls_record(mock_socket)
    assert record == TLS_1_2_HEADER + b"\x00\x05hello"


def test_read_tls_record_invalid():
    """Test reading invalid TLS record."""
    mock_socket = MagicMock()
    mock_socket.read.return_value = b"\x00\x00\x00\x00\x00"
    with pytest.raises(ParserException, match="Not a TLS connection"):
        Tls._read_tls_record(mock_socket)


def test_read_sni_no_sni_extension():
    """Test SNI reading when no SNI is present."""
    mock_socket = MagicMock()

    # We'll construct a minimal Client Hello without extensions
    # Handshake type (1), Length (3), Version (2), Random (32), Session ID (1, length 0),
    # Cipher Suites (2, length 0), Compression (1, length 0)
    client_hello = b"\x01" + b"\x00\x00\x26" + b"\x03\x03" + (b"\x00" * 32) + b"\x00" + b"\x00\x00" + b"\x00"

    # Add record header
    record = TLS_1_2_HEADER + len(client_hello).to_bytes(2, "big") + client_hello

    mock_socket.read.side_effect = [record[:5], record[5:]]

    with pytest.raises(ParserException, match="No extensions present"):
        Tls.read_sni(mock_socket, timeout=5)


def test_read_sni_success():
    """Test successfully extracting SNI."""
    mock_socket = MagicMock()

    # Construct a Client Hello with SNI "example.com"
    sni = b"example.com"
    # Extension: type 0, length, list length, name type 0, name length, name
    ext_data = (
        b"\x00\x00"
        + (len(sni) + 3).to_bytes(2, "big")
        + (len(sni) + 1).to_bytes(2, "big")
        + b"\x00"
        + len(sni).to_bytes(2, "big")
        + sni
    )

    # 2 bytes for total extensions length
    exts = len(ext_data).to_bytes(2, "big") + ext_data

    # Client Hello base (38 bytes)
    client_hello = b"\x01" + b"\x00\x00\x00" + b"\x03\x03" + (b"\x00" * 32) + b"\x00" + b"\x00\x00" + b"\x00"
    # Fix length in client hello
    length = len(client_hello) - 4 + len(exts)
    client_hello = b"\x01" + length.to_bytes(3, "big") + client_hello[4:] + exts

    record = TLS_1_2_HEADER + len(client_hello).to_bytes(2, "big") + client_hello

    mock_socket.read.side_effect = [record[:5], record[5:]]

    hostname = Tls.read_sni(mock_socket, timeout=5)
    assert hostname == "example.com"
