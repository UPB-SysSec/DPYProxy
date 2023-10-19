import socket
from time import time

from exception.ParserException import ParserException
from util.constants import TLS_1_1_HEADER, TLS_1_0_HEADER, TLS_1_2_HEADER


class WrappedSocket:
    """
    Wraps a socket with useful utility functions.
    """

    def __init__(self, timeout: int, _socket: socket.socket, tcp_frag_size=0):
        self.timeout = timeout
        self.buffer = b''
        self.tcp_frag_size = tcp_frag_size
        self.socket = _socket
        self.socket.settimeout(timeout)

    def read(self, size: int) -> bytes:
        """
        Reads specified amount of data from socket. Blocks until amount of data received or timeout.
        :param size: Data to read.
        :return: Read data
        """
        while len(self.buffer) < size:
            self.buffer += self.socket.recv(4096)
        _res = self.buffer[:size]
        self.buffer = self.buffer[size:]
        return _res

    def read_until(self, until: list[bytes], max_len: int = 100) -> bytes:
        """
        Returns all bytes from the socket until and including the given bytes. Also cancels after timeout
        :param until: Bytes until which to receive
        :param max_len: Max length until which to search
        :return: Read data
        """
        start_time = time()
        while len(list(filter(lambda x: x in self.buffer, until))) == 0:
            if len(self.buffer) > max_len:
                raise ParserException(f"Exceeded max length of {max_len} bytes")
            if time()-start_time > self.timeout:
                raise ParserException(f"Exceeded timeout of {self.timeout}s")
            self.buffer += self.socket.recv(4096)
        until = list(filter(lambda x: x in self.buffer, until))[0]
        index = self.buffer.index(until) + len(until)
        _res = self.buffer[:index]
        self.buffer = self.buffer[index:]
        return _res

    def peek(self, size: int) -> bytes:
        """
        Similar to read, but keeps data in buffer.
        """
        while len(self.buffer) < size:
            self.buffer += self.socket.recv(4096)
        return self.buffer[:size]

    def recv(self, size: int, *args, **kwargs) -> bytes:
        """
        Works similar to recv of the wrapped socket. Prepends any bytes still buffered.
        :param size: Size of the buffer to read into.
        :return: Bytes read from the socket
        """
        if len(self.buffer) > 0:
            _res = self.buffer
            self.buffer = b''
        else:
            _res = self.socket.recv(size, *args, **kwargs)
        return _res

    def send(self, data: bytes, *args, **kwargs) -> int:
        """
        Wraps send() of the wrapped socket. Split into tcp fragments if given as value.
        :return: Return value of the wrapped socket's send method
        """
        if self.tcp_frag_size <= 0:
            return self.socket.send(data, *args, **kwargs)
        else:
            # split into fragments and send each separately
            fragments = (data[i:i+self.tcp_frag_size] for i in range(0, len(data), self.tcp_frag_size))
            for fragment in fragments:
                self.socket.send(fragment, *args, **kwargs)
                self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
                self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def close(self):
        """
        Closes the underlying socket.
        """
        self.socket.close()

    def try_close(self):
        """
        Tries to close the underlying socket. If that fails, we ignore the error.
        """
        try:
            self.socket.close()
        except:
            pass

    def inject(self, content: bytes):
        """
        Injects bytes to the front of the buffer. Can be used to write back read data.
        :param content: the bytes to prepend
        :return: None
        """
        self.buffer = content + self.buffer

    def read_tls_record(self) -> bytes:
        """
        Reads the content of the next tls record from the wire with headers. Throws exception if no record is received.
        :return: The contents of the TLS record
        """
        # read record header
        data = self.read(5)

        # check if first 3 bytes are a tls header
        if data[:3] != TLS_1_0_HEADER and data[:3] != TLS_1_1_HEADER and data[:3] != TLS_1_2_HEADER:
            raise ParserException("Not a TLS connection")

        # read record length
        record_length = int.from_bytes(data[3:5], byteorder='big')
        return data + self.read(record_length)

    def read_tls_message(self, peek=False) -> bytes:
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
        while len(message) < len_to_read and int(time() - timestamp) < self.timeout:
            record = self.read_tls_record()
            buffer += record
            message += record[5:]
            if len(message) >= 4:
                # can parse message length
                len_to_read = int.from_bytes(message[1:4], byteorder='big')
        if peek:
            # re-inject all read records
            self.inject(buffer)
        return message

    def read_http_get(self) -> str:
        """
        Reads the first line of a http get request to parse the domain from it.
        :return: host in the get request
        """
        found = False
        data = b''
        i = 12  # GET http://
        # increasingly peek until we find the linebreak
        while not found and i < 200:
            data = self.peek(i)
            if data[i - 1] == b'\n':
                found = True
            else:
                i += 1
        host = data[11:].split(b'/')[0].decode('ASCII')  # cut GET http:// and parse until first slash

        return host

    def read_http_connect(self) -> (str, int):
        """
        Reads the first line of a http connect request.
        :return: host and port from the http connect request.
        """
        # check if first message is a CONNECT method
        header = b'CONNECT '
        data = self.peek(len(header))
        if data != header:
            raise ParserException("Not a CONNECT message")
        try:
            data = self.read_until([b'\n\n', b'\r\n\r\n'])
            first_line = data.decode().split('\n')[0]
            url = first_line.split(' ')[1]

            # Extract the host and port from the URL
            host, port = url.split(':')

            return host, int(port)
        except Exception as e:
            # not a connect method
            raise ParserException(f"Could not read CONNECT method with exception {e}")

    def read_sni(self) -> str:
        """
        Attempts to read the host from the SNI extension. If the client does not send a SNI extension, None is returned.
        :return: host of the sni extension
        """

        try:
            tls_message = self.read_tls_message(peek=True)
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

