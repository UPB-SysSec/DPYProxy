import logging
import threading

from enumerators.TlsVersion import TlsVersion
from modules.http.HttpStrategies import HttpStrategies
from network.protocols.Http import Http
from network.tcp.WrappedTcpSocket import WrappedTcpSocket
from util.constants import STANDARD_SOCKET_RECEIVE_SIZE, TLS_1_0_HEADER, TLS_1_1_HEADER, TLS_1_2_HEADER


class Forwarder:
    def __init__(
        self,
        socket1: WrappedTcpSocket,
        socket1_name: str,
        socket2: WrappedTcpSocket,
        socket2_name: str,
        record_frag: bool = False,
        record_version: str = TlsVersion.DEFAULT.value,
        frag_size: int = 0,
        http_strategy=None,
        http_smuggling_uncensored_url: str = "",
    ):
        self.socket1 = socket1
        self.socket2 = socket2
        self.socket1_name = socket1_name
        self.socket2_name = socket2_name
        self.record_frag = record_frag
        self.record_version = record_version
        self.frag_size = frag_size
        self.http_strategy = http_strategy
        self.http_smuggling_uncensored_url = http_smuggling_uncensored_url

    def start(self):
        # start sending thread
        threading.Thread(
            target=self._forward,
            args=(
                self.socket1,
                self.socket2,
                f"{self.socket1_name}->{self.socket2_name}",
                self.record_frag,
                self.record_version,
                self.http_strategy,
            ),
        ).start()
        # start receiving thread
        threading.Thread(
            target=self._forward,
            args=(
                self.socket2,
                self.socket1,
                f"{self.socket2_name}->{self.socket1_name}",
            ),
        ).start()

    def _forward(
        self,
        from_socket: WrappedTcpSocket,
        to_socket: WrappedTcpSocket,
        direction: str,
        record_frag=False,
        record_version: str = TlsVersion.DEFAULT.value,
        http_strategy=None,
    ):
        """
        Forwards data between two sockets with optional record manipulation. Falls back to forwarding if no TLS records
        can be parsed from the connection anymore.
        :param to_socket: Socket to receive data from.
        :param from_socket: Socket to forward data to.
        :param record_frag: Whether to fragment handshake records
        :return: None
        """
        alter_tls = record_frag or (record_version != TlsVersion.DEFAULT.value)
        try:
            while True:
                # if record frag is configured, it takes precedence over http manipulations
                if alter_tls:
                    # fragment TLS
                    if not self.attempt_tls_fragmentation(
                        from_socket, to_socket, direction, record_frag, record_version
                    ):
                        # turn of record frag and force normal forwarding
                        alter_tls = False
                        continue

                elif http_strategy is not None:
                    if not self.attempt_http_manipulations(from_socket, to_socket, direction, http_strategy):
                        # turn of htt manipulations and force normal forwarding
                        http_strategy = None
                        continue
                else:
                    # normal forwarding
                    data = from_socket.recv(STANDARD_SOCKET_RECEIVE_SIZE)
                    if not data:
                        self.debug("Connection closed, closing both sockets", direction)
                        to_socket.try_close()
                        break
                    else:
                        to_socket.send(data)
            logging.info("### Cancelled forwarding ###")
        except BrokenPipeError as e:
            self.debug(f"Forwarding broken with {e}", direction)
            to_socket.try_close()
        except OSError as e:
            if e.errno == 9:
                # Bad file descriptor, socket closed by other forwarding queue
                to_socket.try_close()
            else:
                self.debug(f"OSError while forwarding, closing sockets: {e}", direction)
                to_socket.try_close()
        except Exception as e:
            self.debug(f"Exception while forwarding: {e}", direction)
            to_socket.try_close()
        self.info(f"{direction}: Closed connection", direction)

    def attempt_http_manipulations(
        self, from_socket: WrappedTcpSocket, to_socket: WrappedTcpSocket, direction: str, http_strategy
    ) -> bool:
        """
        Attempts to parse HTTP requests and apply manipulations if an HTTP strategy is set. Sends the data.

        Returns: True on successful parsing, false otherwise
        """

        if not Http.is_valid_http(from_socket):
            self.debug(
                "Received non-HTTP data, turning off HTTP manipulations for this and following requests", direction
            )
            return False
        # we allow 4k bytes max
        data = from_socket.recv(STANDARD_SOCKET_RECEIVE_SIZE)
        self.debug("Received HTTP data and manipulating request", direction)
        data = HttpStrategies.manipulations(
            data, strategy=http_strategy, http_smuggling_uncensored_url=self.http_smuggling_uncensored_url
        )
        self.debug(f"After applying Manipulation: {data}", direction)
        to_socket.send(data)
        return True

    def attempt_tls_fragmentation(
        self, from_socket: WrappedTcpSocket, to_socket: WrappedTcpSocket, direction: str, record_frag, record_version
    ) -> bool:
        """
        Attempts to parse and fragment TLS handshake records. Sends data if fragmentable, does not if otherwise.

        Returns: True on successful parsing, false otherwise
        """
        try:
            record_header = from_socket.peek(5)
        except Exception:
            self.debug("Could not read record_header bytes. Disabling record fragmentation", direction)
            return False
        base_header = record_header[:3]
        record_len = int.from_bytes(record_header[3:], byteorder="big")
        is_tls = base_header == TLS_1_0_HEADER or base_header == TLS_1_1_HEADER or base_header == TLS_1_2_HEADER
        if not is_tls:
            self.debug(
                f"Received first non-handshake TLS record header: {record_header}. Turning off "
                f"TLS record fragmentation for this and following records",
                direction,
            )
            # did not receive tls record
            return False
        else:
            self.debug("Received TLS handshake record - fragmenting", direction)
        try:
            record = from_socket.read(5 + record_len)
        except Exception:
            self.debug(f"Could not read {record_len} record bytes. Disabling record fragmentation", direction)
            return False
        if record_version != TlsVersion.DEFAULT.value:
            record_version_bytes = bytes.fromhex(record_version)
            record = self.replace_version_in_record_header(record, record_version_bytes)
            base_header = base_header[:1] + record_version_bytes
        if record_frag:
            record = self.fragment_record(base_header, record_len, record[5:])
        to_socket.send(record)
        return True

    def fragment_record(self, record_base_header: bytes, record_length: int, record_body: bytes) -> bytes:
        fragments = [record_body[i : i + self.frag_size] for i in range(0, record_length, self.frag_size)]
        fragmented_message = b""
        for fragment in fragments:
            # construct header
            fragmented_message += record_base_header + int.to_bytes(len(fragment), byteorder="big", length=2)
            fragmented_message += fragment
        return fragmented_message

    def replace_version_in_record_header(self, record: bytes, version: bytes) -> bytes:
        header_to_keep = record[:1]
        record_length_and_body = record[3:]
        return header_to_keep + version + record_length_and_body

    # LOGGER utility functions
    def _logger_string(self, message: str, prefix: str) -> str:
        return f"{prefix}: {message}"

    def debug(self, message: str, prefix: str):
        logging.debug(self._logger_string(message, prefix))

    def info(self, message: str, prefix: str):
        logging.info(self._logger_string(message, prefix))
