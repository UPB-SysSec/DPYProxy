#!/usr/bin/env python3
import sys
from unittest.mock import MagicMock

import dns

for mod in [
    'pylsqpack',
    'aioquic',
    'aioquic.h3',
    'aioquic.h3.connection',
    'aioquic.h3.events',
    'aioquic.quic',
    'aioquic.quic.configuration',
    'aioquic.quic.connection',
    'aioquic.quic.events',
    'dns.quic',
    'dns.quic._asyncio',
    'dns.quic._common',
    'dns.quic._sync',
]:
    sys.modules[mod] = MagicMock()
dns.quic = sys.modules['dns.quic']

import argparse
import json
import logging
import os
import threading
import time
from argparse import ArgumentParser

from enumerators.Modules import Modules
from enumerators.TcpProxyMode import TcpProxyMode
from enumerators.DnsProxyMode import DnsProxyMode
from enumerators.TlsVersion import TlsVersion
from modules.dns.DnsModule import DnsModule
from modules.Module import Module
from modules.tls.TlsModule import TlsModule

def get_shared_dir() -> str:
    try:
        from android.storage import app_storage_path
        return app_storage_path()
    except ImportError:
        return '/tmp'  # fallback for desktop

STATUS_FILE = os.path.join(get_shared_dir(), 'dpyproxy_status.json')
STOP_FILE   = os.path.join(get_shared_dir(), 'dpyproxy_stop')
CONFIG_FILE = os.path.join(get_shared_dir(), 'dpyproxy_config.json')


def load_ui_config() -> dict:
    """Reads config overrides saved by the UI's settings tab, if any."""
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def write_status(status: str, log: str = ''):
    try:
        with open(STATUS_FILE, 'w') as f:
            json.dump({'status': status, 'log': log, 'ts': time.time()}, f)
    except Exception:
        pass

def log_to_file(msg: str):
    try:
        data = {}
        if os.path.exists(STATUS_FILE):
            with open(STATUS_FILE) as f:
                data = json.load(f)
        data['log'] = data.get('log', '') + '\n' + msg
        data['ts'] = time.time()
        with open(STATUS_FILE, 'w') as f:
            json.dump(data, f)
    except Exception:
        pass


class FileLogHandler(logging.Handler):
    def emit(self, record):
        log_to_file(self.format(record))


def extract_activated_modules(parser: ArgumentParser) -> list[Module]:
    def list_of_modules(arg):
        if not arg:
            return []
        return [Modules.__getitem__(x) for x in arg.split(",")]

    general = parser.add_argument_group("Standard options")
    general.add_argument("-h", "--help", action="help")
    general.add_argument("--debug", default=False, action=argparse.BooleanOptionalAction)
    general.add_argument("--disabled_modules", type=list_of_modules, default=[Modules.HTTP])

    args = parser.parse_known_args([])[0]
    return [mod.create_module(parser) for mod in Modules if mod not in args.disabled_modules]


def apply_ui_overrides(args: argparse.Namespace) -> argparse.Namespace:
    """Applies config values saved by the UI's settings tab onto the default args."""
    overrides = load_ui_config()
    for key, value in overrides.items():
        if not hasattr(args, key):
            continue
        if key == 'dns_mode' and isinstance(value, str):
            try:
                value = DnsProxyMode[value]
            except KeyError:
                continue
        setattr(args, key, value)
    return args


def build_default_args() -> argparse.Namespace:
    args = argparse.Namespace(
        # TLS
        tls_disabled_modes=[],
        tls_timeout=10,
        tls_host='localhost',
        tls_port=4433,
        tls_record_version=TlsVersion.DEFAULT.value,
        tls_record_frag=True,
        tls_tcp_frag=True,
        tls_frag_size=100,
        tls_dns_server_ip=None,
        tls_dns_server_port=53,
        tls_forward_proxy_host='localhost',
        tls_forward_proxy_port=None,
        tls_forward_proxy_mode=TcpProxyMode.HTTPS,
        tls_forward_proxy_resolve_address=False,
        # DNS
        dns_mode=DnsProxyMode.AUTO,
        dns_timeout=3,
        dns_host='127.0.0.1',
        dns_port=5533,
        dns_resolver_host=None,
        dns_resolver_port=None,
        dns_censored_domain='www.google.dj',
        dns_compare_ip_ranges=(
            '8.8.4.0/24,8.8.8.0/24,8.34.208.0/20,8.35.192.0/20,23.236.48.0/20,23.251.128.0/19,'
            '34.0.0.0/15,34.2.0.0/16,34.3.0.0/23,34.3.3.0/24,34.3.4.0/24,34.3.8.0/21,34.3.16.0/20,'
            '34.3.32.0/19,34.3.64.0/18,34.4.0.0/14,34.8.0.0/13,34.16.0.0/12,34.32.0.0/11,34.64.0.0/10,'
            '34.128.0.0/10,35.184.0.0/13,35.192.0.0/14,35.196.0.0/15,35.198.0.0/16,35.199.0.0/17,'
            '35.199.128.0/18,35.200.0.0/13,35.208.0.0/12,35.224.0.0/12,35.240.0.0/13,57.140.192.0/18,'
            '64.15.112.0/20,64.233.160.0/19,66.22.228.0/23,66.102.0.0/20,66.249.64.0/19,70.32.128.0/19,'
            '72.14.192.0/18,74.114.24.0/21,74.125.0.0/16,104.154.0.0/15,104.196.0.0/14,104.237.160.0/19,'
            '107.167.160.0/19,107.178.192.0/18,108.59.80.0/20,108.170.192.0/18,108.177.0.0/17,'
            '130.211.0.0/16,136.22.160.0/20,136.22.176.0/21,136.22.184.0/23,136.22.186.0/24,'
            '136.124.0.0/15,142.250.0.0/15,146.148.0.0/17,152.65.208.0/22,152.65.214.0/23,'
            '152.65.218.0/23,152.65.222.0/23,152.65.224.0/19,162.120.128.0/17,162.216.148.0/22,'
            '162.222.176.0/21,172.110.32.0/21,172.217.0.0/16,172.253.0.0/16,173.194.0.0/16,'
            '173.255.112.0/20,192.104.160.0/23,192.158.28.0/22,192.178.0.0/15,193.186.4.0/24,'
            '199.36.154.0/23,199.36.156.0/24,199.192.112.0/22,199.223.232.0/21,207.223.160.0/20,'
            '208.65.152.0/22,208.68.108.0/22,208.81.188.0/22,208.117.224.0/19,209.85.128.0/17,'
            '216.58.192.0/19,216.73.80.0/20,216.239.32.0/19,216.252.220.0/22'
        ),
        dns_block_page_ips=False,
        dns_add_sni=True,
        dns_working_resolver_config='',
        # HTTP
        http_timeout=10,
        http_host='localhost',
        http_port=8080,
        http_strategy=None,
        http_smuggling_uncensored_url='https://www.gov.cn/',
        # General
        debug=False,
        disabled_modules=[Modules.HTTP],
    )
    return apply_ui_overrides(args)


def main():
    # Set up logging to file
    handler = FileLogHandler()
    handler.setFormatter(logging.Formatter('[%(levelname)s] %(name)s: %(message)s'))
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)

    # Clean up stop flag from previous run
    if os.path.exists(STOP_FILE):
        os.remove(STOP_FILE)

    write_status('starting')
    activated_modules: list[Module] = []

    try:
        parsed_args = build_default_args()

        parser = argparse.ArgumentParser(
            description="Proxy for circumventing DPI-based censorship.",
            usage="%(prog)s [options]",
            add_help=False,
        )
        for mod in Modules:
            mod.get_class().register_parameters(parser)

        activated_modules = extract_activated_modules(parser)

        for mod in activated_modules:
            mod.extract_parameters(parsed_args)

        dns_module = next((m for m in activated_modules if isinstance(m, DnsModule)), None)
        tls_module = next((m for m in activated_modules if isinstance(m, TlsModule)), None)
        if dns_module and tls_module:
            logging.info("DNS + TLS modules found — wiring DNS server to TLS module")
            tls_module.set_dns_server(dns_module.server_address)
            tls_module.extract_parameters(parsed_args)

        for mod in activated_modules:
            threading.Thread(target=mod.start, daemon=True).start()
            logging.info(f"Started module: {mod.__class__.__name__}")

        write_status('running')
        logging.info("All modules running.")

        # Keep alive until stop file appears
        while not os.path.exists(STOP_FILE):
            time.sleep(1)

        logging.info("Stop signal received. Shutting down...")
        write_status('stopping')

    except Exception as e:
        logging.error(f"Service error: {e}")
        write_status('error')

    finally:
        for mod in activated_modules:
            try:
                mod.stop()
            except Exception as e:
                logging.warning(f"Error stopping {mod.__class__.__name__}: {e}")
        write_status('stopped')
        logging.info("Stopped.")

if __name__ == '__main__':
    main()
