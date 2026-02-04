import socket

from network.WrappedSocket import WrappedSocket


class WrappedTcpSocket(WrappedSocket):
    """
    Wraps a socket with useful utility functions.
    """

    def __init__(self, timeout: int, _socket: socket.socket, tcp_frag_size=0):
        self.tcp_frag_size = tcp_frag_size
        super().__init__(timeout, _socket)

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
            total_sent = 0
            for fragment in fragments:
                total_sent += self.socket.send(fragment, *args, **kwargs)
                self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
                self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return total_sent
