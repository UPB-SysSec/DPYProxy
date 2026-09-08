import argparse
from unittest.mock import patch

import pytest

from enumerators.Modules import Modules
from modules.dns.DnsModule import DnsModule
from modules.http.HttpModule import HttpModule
from modules.tls.TlsModule import TlsModule
from old_main import extract_activated_modules, main


def test_extract_activated_modules_default():
    """
    Test that the default set of activated modules matches expectations:
    DNS and TLS modules are enabled, while the HTTP module is disabled by default.
    """
    parser = argparse.ArgumentParser(add_help=False)
    for otherModule in Modules:
        otherModule.get_class().register_parameters(parser)

    with patch("sys.argv", ["main.py"]):
        modules = extract_activated_modules(parser)

        # By default, HTTP is disabled, DNS and TLS are enabled
        active_classes = [type(m) for m in modules]
        assert DnsModule in active_classes
        assert TlsModule in active_classes
        assert HttpModule not in active_classes


def test_extract_activated_modules_disable_dns():
    """
    Test that disabling DNS and HTTP modules via CLI parameters correctly results
    in only the TLS module being active.
    """
    parser = argparse.ArgumentParser(add_help=False)
    for otherModule in Modules:
        otherModule.get_class().register_parameters(parser)

    with patch("sys.argv", ["main.py", "--disabled_modules", "DNS,HTTP"]):
        modules = extract_activated_modules(parser)

        active_classes = [type(m) for m in modules]
        assert TlsModule in active_classes
        assert DnsModule not in active_classes
        assert HttpModule not in active_classes


def test_extract_activated_modules_enable_all():
    """
    Test that supplying an empty disabled modules string correctly enables
    all modules (DNS, TLS, and HTTP).
    """
    parser = argparse.ArgumentParser(add_help=False)
    for otherModule in Modules:
        otherModule.get_class().register_parameters(parser)

    with patch("sys.argv", ["main.py", "--disabled_modules", ""]):
        modules = extract_activated_modules(parser)

        active_classes = [type(m) for m in modules]
        assert DnsModule in active_classes
        assert TlsModule in active_classes
        assert HttpModule in active_classes


@patch("old_main.threading.Thread")
@patch("old_main.time.sleep")
def test_main_execution(mock_sleep, mock_thread):
    """
    Test the main entry-point execution flow, ensuring it sets up proxy threads
    and exits gracefully on keyboard interrupt.
    """
    # Make sleep raise KeyboardInterrupt immediately to exit the infinite loop
    mock_sleep.side_effect = KeyboardInterrupt()

    with patch("sys.argv", ["main.py", "--disabled_modules", ""]):
        # Mock module start/stop to avoid actually starting servers
        with patch.object(TlsModule, "set_dns_server") as mock_set_dns:
            with pytest.raises(SystemExit) as exit_info:
                main()

            assert exit_info.value.code == 0

            # Verify integration logic: TlsModule should get DnsModule's server_address
            mock_set_dns.assert_called_once()

            # Verify threading was used for starting (3 threads for 3 modules)
            assert mock_thread.call_count == 3
