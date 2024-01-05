import socket

import dns


class DomainResolver:
    """
    Resolves domains to ip addresses. Can use DNS over TLS or plain DNS.
    """
    # TODO: DOH / DOQ

    @staticmethod
    def resolve_plain(domain: str) -> str:
        """
        Resolves the given domain to an ip address using the system's DNS resolver.
        """
        return socket.gethostbyname(domain)

    @staticmethod
    def resolve_over_dot(domain: str, dns_resolver: str) -> str:
        """
        Resolves the given domain to an ip address using DNS over TLS on the given DNS resolver.
        :param domain: domain name to resolve
        :param dns_resolver: ip address of the DNS resolver
        :return: One ip address for the domain or None
        """
        domain = dns.name.from_text(domain)
        if not domain.is_absolute():
            domain = domain.concatenate(dns.name.root)

        query = dns.message.make_query(domain, dns.rdatatype.A)
        query.flags |= dns.flags.AD
        query.find_rrset(query.additional, dns.name.root, 65535,
                         dns.rdatatype.OPT, create=True, force_unique=True)
        response = dns.query.tls(query, dns_resolver)

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
                        return DomainResolver.resolve_over_dot(str(item.target), dns_resolver)
            return None