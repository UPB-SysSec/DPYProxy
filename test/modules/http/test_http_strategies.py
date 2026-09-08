import pytest

from modules.http.HttpStrategies import HttpStrategies


@pytest.mark.parametrize(
    "strategy, expected_output",
    [
        # Altering HTTP version (1-2)
        (1, b"GET / HTTP/1.1HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (2, b"GET / OPTIONS\r\nHost: example.com\r\n\r\n"),
        # Splitting request line (3-5)
        (3, b"GET / HTTP" + b"\x09" * 14 + b"/1.1\r\nHost: example.com\r\n\r\n"),
        (4, b"GET " + b"1" * 507 + b"/" + b"\x09" * 1434 + b" HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (5, b"GET / " + b"g" * 1013 + b" HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        # Case changes (6-7)
        (6, b"GET / HTTP/1.1\r\nhost: example.com\r\n\r\n"),
        (7, b"GET / HTTP/1.1\r\nHOST: EXAMPLE.COM\r\n\r\n"),
        # Request line whitespaces (8-23)
        (8, b"GET\x09 / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (9, b"\x09GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (10, b"\x0aGET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (11, b"GET\x0b / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (12, b"GET\x0d\x0d / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (13, b"GET /\x09 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (14, b"GET \x09/ HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (15, b"GET \x0c/ HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (16, b"GET \x0d/ HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (17, b"GET /  HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (18, b"GET  / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (19, b"GET / HTTP/1.1\x0a\x09\x0a\x09\r\nHost: example.com\r\n\r\n"),
        (20, b"GET / HTTP/1.1\x0a\x09\r\nHost: example.com\r\n\r\n"),
        (21, b"GET / HTTP/1.1\x0a\x20\x0a\x20\r\nHost: example.com\r\n\r\n"),
        (22, b"GET / HTTP/1.1\x20\x0a\x09\r\nHost: example.com\r\n\r\n"),
        (23, b"GET / HTTP/1.1\x20\r\nHost: example.com\r\n\r\n"),
        # Host header whitespaces (24-37)
        (24, b"GET / HTTP/1.1\r\nHost: example.com\x0a\r\nHost: example.com\r\n\r\n"),
        (25, b"GET / HTTP/1.1\r\nHo\x0ast: example.com\r\nHost: example.com\r\n\r\n"),
        (26, b"GET / HTTP/1.1\r\nHost:\x20\x0a example.com\r\nHost: example.com\r\n\r\n"),
        (27, b"GET / HTTP/1.1\r\nHost:\x09 example.com\r\n\r\n"),
        (28, b"GET / HTTP/1.1\r\nHost: example.com\x09\r\n\r\n"),
        (29, b"GET / HTTP/1.1\r\nHost: \x09example.com\r\n\r\n"),
        (30, b"GET / HTTP/1.1\r\nHost: \x0a\x0aexample.com\r\n\r\n"),
        (31, b"GET / HTTP/1.1\r\nHost: \x0a\x20example.com\r\n\r\n"),
        (32, b"GET / HTTP/1.1\r\nHost: example.com\x0a\r\n\r\n"),
        (33, b"GET / HTTP/1.1\r\n\x20\x0aHost: example.com\r\n\r\n"),
        (34, b"GET / HTTP/1.1\r\nHost:\x20\x20example.com\r\n\r\n"),
        (35, b"GET / HTTP/1.1\r\nHost: example.com\x20\r\n\r\n"),
        (36, b"GET / HTTP/1.1\r\n\x20Host: example.com\r\n\r\n"),
        (37, b"GET / HTTP/1.1\r\nHost:\x20\x20\x20example.com\r\n\r\n"),
        # Path manipulation (38-39)
        (38, b"GET " + b"3" * 1004 + b"/&ultrasurf HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (39, b"GET ?/ HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        # Method manipulation (40-42)
        (40, b"GETGET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (41, b": / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (42, b"HTTP/1.1 / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        # injecting fake host-like headers (43-48)
        (43, b"GET \x20/ HTTP/1.1\r\n" + b"/" * 64 + b" /?ultrasurf\r\nHost: example.com\r\n\r\n"),
        (44, b"GET / HTTP/1.1\r\n" + b"a" * 64 + b" example.com\r\nHost: example.com\r\n\r\n"),
        (45, b"GET\x09 / HTTP/1.1\r\n" + b"a" * 64 + b" example.com\r\nHost: example.com\r\n\r\n"),
        (46, b"\x0aGET / HTTP/1.1\r\n" + b"/" * 64 + b" example.com\r\nHost: example.com\r\n\r\n"),
        (47, b"GET\x20 / HTTP/1.1\r\n" + b"/" * 64 + b" example.com\r\nHost: example.com\r\n\r\n"),
        (48, b"\x20GET / HTTP/1.1\r\n example.com\r\nHost: example.com\r\n\r\n"),
        # extra-large padding strings in path, version, host, or method (49-70)
        (49, b"GET " + b"/" * 1434 + b" HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (50, b"GET / HTTP/1.1\r\nHost:\x20" + b"\x20" * 1413 + b"example.com\r\n\r\n"),
        (51, b"GET / HTTP/1.1\r\nHost:\x20" + b"\x20" * 1434 + b"example.com\r\n\r\n"),
        (52, b"GET" + b"a" * 1407 + b" / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (53, b"GET" + b"\x09" * 2568 + b" / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (54, b"\x0a" * 4336 + b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (55, b"GET" + b"\x20" * 1413 + b" / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (56, b"GET" + b"\x20" * 1720 + b" / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (57, b"GET " + b"a" * 1409 + b"/ HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (58, b"GET /" + b"\x0d" * 1434 + b" HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (59, b"GET /" + b"\x20" * 1413 + b" HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (60, b"GET &" + b"3" * 511 + b" HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (61, b"GET /" + b"\x23" * 1413 + b" HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (62, b"GET /# HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (63, b"GET /" + b"\x3f" * 1413 + b" HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (64, b"GET " + b"\x3f" * 1413 + b"/ HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (65, b"GET " + b"/" * 1414 + b" HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (66, b"GET / HTTP/1.1" + b"\x20" * 1434 + b"\r\nHost: example.com\r\n\r\n"),
        (67, b"GET / " + b"\x20" * 1434 + b"HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (68, b"GET / HTTP" + b"\x25" * 1434 + b"/1.1\r\nHost: example.com\r\n\r\n"),
        (69, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (70, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
    ],
)
def test_basic_strategies_exact_output(strategy, expected_output):
    """
    Test each basic strategy to ensure it modifies the HTTP request exactly as expected.
    """
    request_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    smuggling_url = "https://www.example.com/"

    actual = HttpStrategies.manipulations(request_data, strategy, smuggling_url)
    assert actual == expected_output


# Define base variables for smuggling expected outputs
clte_base = b"GET / HTTP/1.1\r\nHost: www.example.com\r\n"
clte_suffix = b"\r\n0\r\n\r\nGET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

tecl_base = b"GET / HTTP/1.1\r\nHost: www.example.com\r\nContent-Length: 0\r\n"
tecl_suffix = b"\r\n10\r\nGET / HTTP/1.1\r\n\r\n13\r\nHost: example.com\r\n\r\n0\r\n\r\n"


@pytest.mark.parametrize(
    "strategy, expected_output",
    [
        # CLTE Content-Length manipulations (101-112)
        (101, clte_base + b"Content-Length:: 42\r\nTransfer-Encoding: chunked\r\n" + clte_suffix),
        (102, clte_base + b"Content-Length : 42 \r\nTransfer-Encoding: chunked\r\n" + clte_suffix),
        (103, clte_base + b"Content-Length\t: 42\t\r\nTransfer-Encoding: chunked\r\n" + clte_suffix),
        (104, clte_base + b"Content-Length: '42'\r\nTransfer-Encoding: chunked\r\n" + clte_suffix),
        (105, clte_base + b"Content-Length:  42 \r\nTransfer-Encoding: chunked\r\n" + clte_suffix),
        (106, clte_base + b"Content-Length: 42 \nX: X\r\nTransfer-Encoding: chunked\r\n" + clte_suffix),
        (107, clte_base + b"Content-Length: 42\nX: X\r\nTransfer-Encoding: chunked\r\n" + clte_suffix),
        (108, clte_base + b"Content-Length:\x0b 42\r\nTransfer-Encoding: chunked\r\n" + clte_suffix),
        (109, clte_base + b"Content-Length: 42\n\nX: X\r\nTransfer-Encoding: chunked\r\n" + clte_suffix),
        (110, clte_base + b"Content-Length: 42\n\r\nTransfer-Encoding: chunked\r\n" + clte_suffix),
        (111, clte_base + b"Content_Encoding: 42\r\nTransfer-Encoding: chunked\r\n" + clte_suffix),
        (112, clte_base + b"Content-Length: 42\r\nTransfer-Encoding: chunked\r\n" + clte_suffix),
        # TECL Transfer-Encoding manipulations (113-120)
        (113, tecl_base + b"Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n" + tecl_suffix),
        (114, tecl_base + b"Transfer-Encoding: chunked\r\n Transfer-Encoding: chunked\r\n" + tecl_suffix),
        (115, tecl_base + b" Transfer-Encoding: chunked \r\n" + tecl_suffix),
        (116, tecl_base + b"\tTransfer-Encoding: chunked\t\r\n" + tecl_suffix),
        (117, tecl_base + b"Transfer-Encoding\r: chunked\r\r\n" + tecl_suffix),
        (118, tecl_base + b"Content-Encoding: chunked\r\n" + tecl_suffix),
        (119, tecl_base + b"Transfer-Encoding: chunked\r\n" + tecl_suffix),
        (120, tecl_base + b"Transfer_Encoding: chunked\r\n" + tecl_suffix),
        # CLTE Transfer-Encoding casing/spacing (121-127)
        (121, clte_base + b"Content-Length: 42\r\nTRANSFER-ENCODING: CHUNKED\r\n" + clte_suffix),
        (122, clte_base + b"Content-Length: 42\r\nTrAnSFer-EnCODinG: cHuNkeD\r\n" + clte_suffix),
        (123, clte_base + b"Content-Length: 42\r\nTransfer-Encoding:: chunked\r\n" + clte_suffix),
        (124, clte_base + b"Content-Length: 42\r\nTransfer-Encoding : chunked \r\n" + clte_suffix),
        (125, clte_base + b"Content-Length: 42\r\nTransfer-Encoding\t: chunked\t\r\n" + clte_suffix),
        (126, clte_base + b"Content-Length: 42\r\nTransfer-Encoding:\n chunked\r\n" + clte_suffix),
        (127, clte_base + b"Content-Length: 42\r\n\nTransfer-Encoding: chunked\n\r\n" + clte_suffix),
        # No manipulation direct request smuggling (128-129)
        (128, clte_base + b"Content-Length: 42\r\nTransfer-Encoding: chunked\r\n" + clte_suffix),
        (129, b"GET / HTTP/1.1\r\nHost: www.example.com\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n"),
    ],
)
def test_smuggling_strategies_exact_output(strategy, expected_output):
    """
    Test each smuggling strategy to ensure it modifies the HTTP request exactly as expected.
    """
    request_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    smuggling_url = "https://www.example.com/"

    actual = HttpStrategies.manipulations(request_data, strategy, smuggling_url)
    assert actual == expected_output
