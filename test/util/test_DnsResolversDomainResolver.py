from unittest.mock import MagicMock, patch


def test_dns_resolvers_domain_resolver(capsys):
    """
    Test the DnsResolversDomainResolver script by mocking the resolve call
    to prevent actual network requests.
    """
    # Mock resolve_udp_static to simulate a successful DNS response
    with patch("network.DomainResolver.DomainResolver.resolve_udp_static") as mock_resolve:
        mock_msg = MagicMock()
        mock_resolve.return_value = mock_msg

        # Mock parse_all_ips to return the expected IP for the resolver
        with patch("util.DnsResolversDomainResolver.parse_all_ips") as mock_parse:
            # just return a dummy IP
            mock_parse.return_value = ["1.2.3.4"]

    captured = capsys.readouterr()
    # print 'Ip mismatch' for the resolvers since 1.2.3.4 is not their correct IP
    assert "Ip mismatch" in captured.out
