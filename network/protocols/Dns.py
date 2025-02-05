from dns.message import Message, make_response

from exception.DnsException import DnsException
from network.DomainResolver import DomainResolver
from network.WrappedSocket import WrappedSocket

import dns

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
    def query_from_domain(domain: str) -> dns.message.Message:
        domain = dns.name.from_text(domain)
        if not domain.is_absolute():
            domain = domain.concatenate(dns.name.root)

        query = dns.message.make_query(domain, dns.rdatatype.A)
        query.flags |= dns.flags.AD
        query.find_rrset(query.additional, dns.name.root, 65535,
                         dns.rdatatype.OPT, create=True, force_unique=True)
        return query

    @staticmethod
    def ip_from_response(response: dns.message.Message, domain_resolver: DomainResolver) -> str:
        if response.rcode() != dns.rcode.NOERROR:
            return None

        # filter ipv4 answer
        ips = []
        for record in response.answer:
            if record.rdtype == dns.rdatatype.A:
                for item in record.items:
                    ips.append(str(item.address))
        if len(ips) > 0:
            return ips[0]
        else:
            # read CNAME hostnames from answer
            for record in response.answer:
                if record.rdtype == dns.rdatatype.CNAME:
                    for item in record.items:
                        return domain_resolver.resolve(str(item.target))
            return None

    @staticmethod
    def make_response(message: Message, orig_id: int) -> Message:
        """
        Creates a DNS response message to the given query. Replaces the answers id with the original id. Necessary for
        DoQ and maybe DoH as they set the id to 0.
        """
        answer = make_response(message)
        answer.id = orig_id
        return answer