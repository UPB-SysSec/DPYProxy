import socket
import threading
import time

import pytest

from modules.tls.TcpProxy import TcpProxy
from network.NetworkAddress import NetworkAddress
from test.Sink import Sink

NETWORK_ADDRESS = NetworkAddress("127.0.0.1", 8090)
CONNECT_DATA = "CONNECT 127.0.0.1:8091 HTTP/1.1\r\n\r\n"
HTTP_REQUEST = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"


@pytest.fixture(scope="module")
def setup_sink():
    sink = Sink("127.0.0.1", 8091)
    sink.start()
    yield sink
    sink.close()


def test_basic_manipulation(setup_sink):
    data = run_server(TcpProxy(address=NETWORK_ADDRESS, http_strategy=2), setup_sink)
    assert data.decode() == "GET / OPTIONS\r\nHost: example.com\r\n\r\n"


def test_smuggling_manipulation(setup_sink):
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
    time.sleep(1)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", 8090))
        s.sendall(CONNECT_DATA.encode())
        time.sleep(1)
        s.sendall(HTTP_REQUEST.encode())
    ret = sink.receive_message()
    proxy.server.close()
    thread.join()
    return ret
