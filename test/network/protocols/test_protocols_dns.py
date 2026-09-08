import dns.message
import pytest

from exception.DnsException import DnsException
from network.protocols.Dns import Dns


def test_read_dns_success():
    """Test reading a valid DNS wire format."""
    query = dns.message.make_query("example.com", dns.rdatatype.A)
    msg = Dns.read_dns(query.to_wire())
    assert msg.question[0].name.to_text() == "example.com."


def test_read_dns_exception():
    """Test reading invalid DNS wire format raises exception."""
    with pytest.raises(DnsException):
        Dns.read_dns(b"invalid_data")


def test_make_response():
    """Test making a response and preserving original ID."""
    query = dns.message.make_query("example.com", dns.rdatatype.A)
    orig_id = 12345
    response = Dns.make_response(query, orig_id)
    assert response.id == orig_id
