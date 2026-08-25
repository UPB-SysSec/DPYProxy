import argparse
import socket
import threading
import time

import pytest

from modules.http.HttpModule import HttpModule
from modules.tls.TcpProxy import TcpProxy
from network.NetworkAddress import NetworkAddress
from test.Sink import Sink

NETWORK_ADDRESS = NetworkAddress("127.0.0.1", 8090)
CONNECT_DATA = "CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n"
HTTP_REQUEST = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"


@pytest.fixture(scope="module")
def setup_sink():
    # Open a temporary socket to get a free port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as temp_sock:
        # Force OS to release the port immediately after closing
        temp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        temp_sock.bind(("127.0.0.1", 0))
        free_port = temp_sock.getsockname()[1]
    sink = Sink("127.0.0.1", free_port)
    sink.start()
    yield sink
    sink.close()


def test_basic_manipulation(setup_sink):
    """
    Test that a basic HTTP manipulation strategy (strategy 2) correctly
    alters the HTTP version field when routed through the proxy.
    """
    data = run_server(TcpProxy(address=NETWORK_ADDRESS, http_strategy=2), setup_sink)
    assert data.decode() == "GET / OPTIONS\r\nHost: example.com\r\n\r\n"


def test_smuggling_manipulation(setup_sink):
    """
    Test that an HTTP Request Smuggling strategy (strategy 101) correctly formats
    the smuggled request (prepended CLTE request and chunked body) and routes
    it through the proxy.
    """
    data = run_server(
        TcpProxy(address=NETWORK_ADDRESS, http_strategy=101, http_smuggling_uncensored_url="https://www.gov.cn/"),
        setup_sink,
    )
    assert (
        data.decode()
        == "GET / HTTP/1.1\r\nHost: www.gov.cn\r\nContent-Length:: 42\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    )


def run_server(proxy: TcpProxy, sink: Sink) -> bytes:
    """
    Runs the test and return the bytes sent from the proxy to the sink server.
    """
    thread = threading.Thread(target=proxy.start)
    thread.start()
    time.sleep(0.5)
    connect_data = CONNECT_DATA.format(sink.port)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", 8090))
        s.sendall(connect_data.encode())
        time.sleep(0.5)
        s.sendall(HTTP_REQUEST.encode())
    ret = sink.receive_message()
    proxy.server.close()
    thread.join()
    return ret


def test_http_module_extract_parameters():
    """
    Test the extraction of HTTP-specific CLI configuration arguments and their
    proper application to the HttpModule instance.
    """
    parser = argparse.ArgumentParser()
    HttpModule.register_parameters(parser)
    module = HttpModule(parser)

    # Simulate parsed arguments
    args = argparse.Namespace(
        http_host="192.168.1.2",
        http_port=8080,
        http_timeout=20,
        http_strategy=105,
        http_smuggling_uncensored_url="https://example.com",
        proxy_mode=None,
    )

    module.extract_parameters(args)

    assert module.proxy is not None
    assert module.proxy.address.host == "192.168.1.2"
    assert module.proxy.address.port == 8080
    assert module.proxy.timeout == 20
    assert module.proxy.http_strategy == 105
    assert module.proxy.http_smuggling_uncensored_url == "https://example.com"
