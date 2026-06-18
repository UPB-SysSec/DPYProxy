from enum import Enum


class HttpMethod(Enum):
    GET = "GET"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"
    PUT = "PUT"
    POST = "POST"
    DELETE = "DELETE"
    PATCH = "PATCH"
    CONNECT = "CONNECT"

    @staticmethod
    def all():
        return [e.value for e in HttpMethod]
