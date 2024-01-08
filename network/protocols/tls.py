from time import time

from exception.ParserException import ParserException
from network.WrappedSocket import WrappedSocket
from util.constants import TLS_1_0_HEADER, TLS_1_1_HEADER, TLS_1_2_HEADER


class TlsParser:
    @staticmethod
    def read_sni(wrapped_socket: WrappedSocket, timeout: int) -> str:
        """
        Attempts to read the host from the SNI extension. If the client does not send a SNI extension, None is returned.
        :return: host of the sni extension
        """

        try:
            tls_message = TlsParser._read_tls_message(wrapped_socket, peek=True, timeout=timeout)
        except ParserException as e:
            raise e
        except Exception as e:
            raise ParserException(e)

        # check if record is a client hello
        if tls_message[0] != 0x01:
            raise ParserException("Not a client hello")

        # skip everything until SNI extension
        p = 38
        # session_id
        p += 1 + int.from_bytes(tls_message[p:p + 1], byteorder='big')
        # cipher suites
        p += 2 + int.from_bytes(tls_message[p:p + 2], byteorder='big')
        # compression methods
        p += 1 + int.from_bytes(tls_message[p:p + 1], byteorder='big')

        if p >= len(tls_message):
            raise ParserException("No extensions present")

        # extensions
        p += 2

        while p < len(tls_message):
            ext_type = int.from_bytes(tls_message[p:p + 2], byteorder='big')
            p += 2
            ext_length = int.from_bytes(tls_message[p:p + 2], byteorder='big')
            p += 2

            if ext_type != 0:
                # skip over not sni
                p += ext_length
            else:
                # sni
                list_len = int.from_bytes(tls_message[p:p + 2], byteorder='big')
                p += 2
                _list_len = p + list_len
                while p < _list_len:
                    name_type = int.from_bytes(tls_message[p:p + 1], byteorder='big')
                    p += 1
                    name_len = int.from_bytes(tls_message[p:p + 2], byteorder='big')
                    p += 2
                    if name_type != 0:
                        # unknown name type, skip
                        p += name_len
                    else:
                        # hostname
                        hostname = tls_message[p:p + name_len]
                        return hostname.decode("ASCII")
        raise ParserException("No SNI present")

    @staticmethod
    def _read_tls_message(wrapped_socket: WrappedSocket, timeout: int, peek=False) -> bytes:
        """
        Reads the content of the next tls message from the socket.
        :param: whether to peek the tls message.
        :return: The content of the TLS message
        """
        message = b''
        buffer = b''
        # headers
        len_to_read = 4
        # prevent infinite sockets
        timestamp = time()
        # parse records until message complete
        while len(message) < len_to_read and int(time() - timestamp) < timeout:
            record = TlsParser._read_tls_record(wrapped_socket)
            buffer += record
            message += record[5:]
            if len(message) >= 4:
                # can parse message length
                len_to_read = int.from_bytes(message[1:4], byteorder='big')
        if peek:
            # re-inject all read records
            wrapped_socket.inject(buffer)
        return message

    @staticmethod
    def _read_tls_record(wrapped_socket: WrappedSocket, ) -> bytes:
        """
        Reads the content of the next tls record from the wire with headers. Throws exception if no record is received.
        :return: The contents of the TLS record
        """
        # read record header
        data = wrapped_socket.read(5)

        # check if first 3 bytes are a tls header
        if data[:3] != TLS_1_0_HEADER and data[:3] != TLS_1_1_HEADER and data[:3] != TLS_1_2_HEADER:
            raise ParserException("Not a TLS connection")

        # read record length
        record_length = int.from_bytes(data[3:5], byteorder='big')
        return data + wrapped_socket.read(record_length)
