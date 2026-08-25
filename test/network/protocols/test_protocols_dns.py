from unittest.mock import MagicMock

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


def test_query_from_domain():
    """Test generating query from domain string."""
    query = Dns.query_from_domain("example.com")
    assert query.question[0].name.to_text() == "example.com."
    assert query.question[0].rdtype == dns.rdatatype.A
    assert query.flags & dns.flags.AD


def test_ip_from_response_success():
    """Test extracting IP from valid DNS response."""
    response = dns.message.make_query("example.com", dns.rdatatype.A)
    response.set_rcode(dns.rcode.NOERROR)

    mock_record = MagicMock()
    mock_record.rdtype = dns.rdatatype.A
    mock_item = MagicMock()
    mock_item.address = "1.2.3.4"
    mock_record.items = [mock_item]
    response.answer = [mock_record]

    mock_resolver = MagicMock()

    ip = Dns.ip_from_response(response, mock_resolver)
    assert ip == "1.2.3.4"


def test_ip_from_response_cname():
    """Test extracting IP from CNAME response via recursive resolution."""
    response = dns.message.make_query("example.com", dns.rdatatype.A)
    response.set_rcode(dns.rcode.NOERROR)

    mock_record = MagicMock()
    mock_record.rdtype = dns.rdatatype.CNAME
    mock_item = MagicMock()
    mock_item.target = "cname.example.com."
    mock_record.items = [mock_item]
    response.answer = [mock_record]

    mock_resolver = MagicMock()
    mock_resolver.resolve.return_value = "5.6.7.8"

    ip = Dns.ip_from_response(response, mock_resolver)
    assert ip == "5.6.7.8"
    mock_resolver.resolve.assert_called_once_with("cname.example.com.")


def test_make_response():
    """Test making a response and preserving original ID."""
    query = dns.message.make_query("example.com", dns.rdatatype.A)
    orig_id = 12345
    response = Dns.make_response(query, orig_id)
    assert response.id == orig_id
