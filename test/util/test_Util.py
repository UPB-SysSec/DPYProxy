from unittest.mock import MagicMock

import dns.message
from dns.rdatatype import RdataType

from util.Util import is_valid_ipv4_address, parse_all_ips


def test_is_valid_ipv4_address():
    """Test IPv4 validation utility."""
    assert is_valid_ipv4_address("192.168.1.1") is True
    assert is_valid_ipv4_address("8.8.8.8") is True
    assert is_valid_ipv4_address("invalid_ip") is False
    assert is_valid_ipv4_address("256.256.256.256") is False


def test_parse_all_ips_success():
    """Test extracting IPs from a DNS response with A records."""
    mock_msg = MagicMock(spec=dns.message.Message)
    mock_question = MagicMock()
    mock_question.name = "example.com"
    mock_question.rdclass = 1
    mock_question.rdtype = RdataType.A
    mock_msg.question = [mock_question]

    mock_record = MagicMock()
    mock_record.address = "1.2.3.4"
    mock_msg.find_rrset.return_value = [mock_record]

    ips = parse_all_ips(mock_msg)
    assert ips == ["1.2.3.4"]


def test_parse_all_ips_cname_fallback():
    """Test extracting IPs from a DNS response using CNAME fallback."""
    mock_msg = MagicMock(spec=dns.message.Message)
    mock_question = MagicMock()
    mock_question.name = "example.com"
    mock_question.rdclass = 1
    mock_question.rdtype = RdataType.A
    mock_msg.question = [mock_question]

    mock_cname_record = MagicMock()
    mock_cname_record.__str__.return_value = "cname.example.com"

    mock_a_record = MagicMock()
    mock_a_record.address = "5.6.7.8"

    def side_effect(answer, name, rdclass, rdtype):
        if rdtype == RdataType.A and name == "example.com":
            raise Exception("No A record")
        elif rdtype == RdataType.CNAME:
            return [mock_cname_record]
        elif rdtype == RdataType.A and name == "cname.example.com":
            return [mock_a_record]
        return []

    mock_msg.find_rrset.side_effect = side_effect

    ips = parse_all_ips(mock_msg)
    assert ips == ["5.6.7.8"]


def test_parse_all_ips_none_message():
    """Test extracting IPs when message is None."""
    ips = parse_all_ips(None)
    assert ips == []
