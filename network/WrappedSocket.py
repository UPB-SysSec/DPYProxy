import socket
from time import time

from exception.ParserException import ParserException
from util.constants import STANDARD_SOCKET_RECEIVE_SIZE


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
            self.buffer += self.socket.recv(STANDARD_SOCKET_RECEIVE_SIZE)
        _res = self.buffer[:size]
        self.buffer = self.buffer[size:]
        return _res

    def read_until(self, until: list[bytes], max_len: int = 100, peek: bool = False) -> bytes:
        """
        Returns all bytes from the socket until and including the given bytes. Also cancels after timeout
        :param until: Bytes until which to receive
        :param max_len: Max length until which to search
        :param peek: Whether to keep the bytes in the buffer
        :return: Read data
        """
        start_time = time()
        while len(list(filter(lambda x: x in self.buffer, until))) == 0:
            if len(self.buffer) > max_len:
                raise ParserException(f"Exceeded max length of {max_len} bytes")
            if time()-start_time > self.timeout:
                raise ParserException(f"Exceeded timeout of {self.timeout}s")
            self.buffer += self.socket.recv(STANDARD_SOCKET_RECEIVE_SIZE)
        until = list(filter(lambda x: x in self.buffer, until))[0]
        index = self.buffer.index(until) + len(until)
        _res = self.buffer[:index]
        if not peek:
            self.buffer = self.buffer[index:]
        return _res

    def peek(self, size: int) -> bytes:
        """
        Similar to read, but keeps data in buffer.
        """
        while len(self.buffer) < size:
            self.buffer += self.socket.recv(STANDARD_SOCKET_RECEIVE_SIZE)
        return self.buffer[:size]

    def recv(self, size: int, *args, **kwargs) -> bytes:
        """
        Works similar to recv of the wrapped socket. Prepends any bytes still buffered.
        :param size: Size of the buffer to read into.
        :return: Bytes read from the socket
        """

        # copy any left bytes from buffer
        _res = self.buffer[:min(size, len(self.buffer))]
        self.buffer = self.buffer[min(size, len(self.buffer)):]

        if len(_res) < size:
            # read rest from socket
            _res += self.socket.recv(size-len(_res), *args, **kwargs)
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
        self.socket.shutdown(socket.SHUT_RDWR)
        self.socket.close()

    def try_close(self):
        """
        Tries to close the underlying socket. If that fails, we ignore the error.
        """
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
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
