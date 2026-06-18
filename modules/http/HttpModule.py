import logging
from argparse import ArgumentParser, Namespace

from modules.http.HttpStrategies import HttpStrategies
from modules.Module import Module
from modules.tls.TcpProxy import TcpProxy
from network.NetworkAddress import NetworkAddress


class HttpModule(Module):
    """
    Implements circumvention methods for the HTTP censorship.
    Only one technique allowed at a time. Can not combine direct
    HTTP manipulations and HTTP request smuggling strategies.
    (falls back to direct manipulation in that case)
    """

    def __init__(self, parser: ArgumentParser):
        super().__init__(parser)

    @staticmethod
    def register_parameters(parser: ArgumentParser):

        http_module = parser.add_argument_group("HTTP Module")

        http_module.add_argument("--http_timeout", type=int, default=10, help="Connection timeout in seconds")

        http_module.add_argument("--http_host", type=str, default="localhost", help="Address the proxy server runs on")

        http_module.add_argument("--http_port", type=int, default=8080, help="Port the proxy server runs on")

        http_module.add_argument(
            "--http_strategy",
            type=int,
            default=None,
            help="Number of which specific http manipulation strategy to apply. "
            "None: no manipulation, [1..70]: basic manipulations, [101, 129]: Smuggling."
            "See HttpStrategies for meaning.",
        )

        http_module.add_argument(
            "--http_smuggling_uncensored_url",
            type=str,
            default="https://www.gov.cn/",
            help="Uncensored url to use for http smuggling.",
        )

    def extract_parameters(self, args: Namespace):
        server_address = NetworkAddress(args.http_host, args.http_port)

        if args.http_strategy is not None and not HttpStrategies.strategy_is_valid(args.http_strategy):
            logging.error(
                f"Invalid http strategy specified. Provided: {args.http_strategy}, Allowed: None: no manipulation,"
                f" [1..70]: basic manipulations, [101, 129]: Smuggling."
            )

        self.proxy = TcpProxy(
            address=server_address,
            timeout=args.http_timeout,
            http_strategy=args.http_strategy,
            http_smuggling_uncensored_url=args.http_smuggling_uncensored_url,
        )

    def start(self):
        self.proxy.start()

    def stop(self):
        self.proxy.continue_processing = False
        logging.info("Waiting for proxy to stop")
