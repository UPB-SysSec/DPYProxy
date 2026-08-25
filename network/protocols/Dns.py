import dns
from dns.message import Message, make_response

from exception.DnsException import DnsException


class Dns:
    """
    Implements methods to parse DNS messages.
    """

    DNS_MAX_SIZE = 512

    @staticmethod
    def read_dns(message: bytes) -> dns.message.Message:
        try:
            return dns.message.from_wire(message)
        except Exception as e:
            raise DnsException(f"Could not parse DNS message: {e}")

    @staticmethod
    def make_response(message: Message, orig_id: int) -> Message:
        """
        Creates a DNS response message to the given query. Replaces the answers id with the original id. Necessary for
        DoQ and maybe DoH as they set the id to 0.
        """
        answer = make_response(message)
        answer.id = orig_id
        return answer
