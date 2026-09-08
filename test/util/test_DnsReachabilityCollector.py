from util.DnsReachabilityCollector import format_time, main


def test_dns_reachability_collector_main(capsys):
    """Test the main method (currently returns early)."""
    main()
    captured = capsys.readouterr()
    assert "8.8.4.0/24" in captured.out


def test_format_time():
    """Test the time formatting utility."""
    assert format_time(3661.0) == "01:01:01"
    assert format_time(0.0) == "00:00:00"
