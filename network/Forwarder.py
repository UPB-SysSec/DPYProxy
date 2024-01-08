import logging
import threading

from network.WrappedSocket import WrappedSocket
from util.constants import STANDARD_SOCKET_RECEIVE_SIZE, TLS_1_0_HEADER, TLS_1_2_HEADER, TLS_1_1_HEADER


class Forwarder:

    def __init__(self, socket1: WrappedSocket, socket1_name: str, socket2: WrappedSocket, socket2_name: str,
                 record_frag: bool = False, frag_size: int = 0):
        self.socket1 = socket1
        self.socket2 = socket2
        self.socket1_name = socket1_name
        self.socket2_name = socket2_name
        self.record_frag = record_frag
        self.frag_size = frag_size

    def start(self):
        threading.Thread(target=self._forward, args=(self.socket1,
                                                     self.socket2,
                                                     f"{self.socket1_name}->{self.socket2_name}",
                                                     self.record_frag)).start()
        threading.Thread(target=self._forward, args=(self.socket2,
                                                     self.socket1,
                                                     f"{self.socket2_name}->{self.socket1_name}",
                                                     )).start()

    def _forward(self, from_socket: WrappedSocket, to_socket: WrappedSocket, direction: str, record_frag=False):
        """
        Forwards data between two sockets with optional record fragmentation. Falls back to forwarding if no TLS records
        can be parsed from the connection anymore.
        :param to_socket: Socket to receive data from.
        :param from_socket: Socket to forward data to.
        :param record_frag: Whether to fragment handshake records
        :return: None
        """
        try:
            while True:
                if not record_frag:
                    data = from_socket.recv(STANDARD_SOCKET_RECEIVE_SIZE)
                    if not data:
                        self.debug("Connection closed, closing both sockets", direction)
                        to_socket.try_close()
                        break
                    else:
                        to_socket.send(data)
                else:
                    try:
                        record_header = from_socket.peek(5)
                    except:
                        self.debug("Could not read record_header bytes. Disabling record fragmentation", direction)
                        record_frag = False
                        continue
                    base_header = record_header[:3]
                    record_len = int.from_bytes(record_header[3:], byteorder='big')
                    is_tls = base_header == TLS_1_0_HEADER or base_header == TLS_1_1_HEADER \
                             or base_header == TLS_1_2_HEADER
                    if not is_tls:
                        self.debug(f"Received first non-handshake TLS record header: {record_header}. Turning off "
                                   f"TLS record fragmentation for this and following records", direction)
                        # did not receive tls record
                        record_frag = False
                        continue
                    else:
                        self.debug("Received TLS handshake record - fragmenting", direction)
                    try:
                        record = from_socket.read(5 + record_len)[5:]
                    except:
                        self.debug(f"Could not read {record_len} record bytes. Disabling record fragmentation",
                                   direction)
                        record_frag = False
                        continue
                    fragments = [record[i:i + self.frag_size] for i in range(0, record_len, self.frag_size)]
                    fragmented_message = b''
                    for fragment in fragments:
                        # construct header
                        fragmented_message += base_header + int.to_bytes(len(fragment), byteorder='big', length=2)
                        fragmented_message += fragment
                    to_socket.send(fragmented_message)
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

    # LOGGER utility functions
    def _logger_string(self, message: str, prefix: str) -> str:
        return f"{prefix}: {message}"

    def debug(self, message: str, prefix: str):
        logging.debug(self._logger_string(message, prefix))

    def info(self, message: str, prefix: str):
        logging.info(self._logger_string(message, prefix))
