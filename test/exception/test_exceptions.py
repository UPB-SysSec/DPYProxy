from exception.DnsException import DnsException
from exception.ParserException import ParserException


def test_dns_exception():
    """Test DnsException creation and message formatting."""
    exc = DnsException("DNS resolution failed")
    assert str(exc) == "(('DNS resolution failed',), {})"


def test_parser_exception():
    """Test ParserException creation and message formatting."""
    exc = ParserException("Parsing error occurred")
    assert str(exc) == "(('Parsing error occurred',), {})"
