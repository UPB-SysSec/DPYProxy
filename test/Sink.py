import socket


class Sink:
    def __init__(self, ip: str, port: int):
        self.socket = None
        self.ip = ip
        self.port = port

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.ip, self.port))
        server.settimeout(5)
        server.listen()
        self.socket = server

    def close(self):
        self.socket.close()

    def receive_message(self):
        conn, addr = self.socket.accept()
        with conn:
            return conn.recv(65535)
