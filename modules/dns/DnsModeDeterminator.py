import logging
from doctest import Example

from enumerators.DnsProxyMode import DnsProxyMode
from enumerators.Port import Port
from modules.dns.DnsResolver import DnsResolver
from network.DomainResolver import DomainResolver
from network.NetworkAddress import NetworkAddress

from dns.message import make_query


class DnsModeDeterminator:
    """
    Determines functioning circumvention modes and reachable DoQ/DoH/etc. servers.
    """

    @staticmethod
    def parse_resolvers(resolvers:list[tuple[DnsProxyMode, str, str, int]]) -> list[DnsResolver]:
        _ret = []
        for resolver in resolvers:
            address = NetworkAddress(resolver[2], resolver[3])
            _ret += [DnsResolver(resolver[1], address, resolver[0])]
        return _ret


    EXAMPLE_REQUEST = make_query("www.wikipedia.org", "A")

    # extend with https://en.wikipedia.org/wiki/Public_recursive_name_server

    # TODO adguard
    # TODO cloudflare family and security?
    # TODO mullvad
    # TODO cisco umberalla?
    # TODO quad 9 backups ?
    # TODO yandex


    CLOUDFLARE_DNS_1 = "1.1.1.1"
    CLOUDFLARE_DNS_2 = "1.0.0.1"
    GOOGLE_DNS_1 = "8.8.8.8"
    GOOGLE_DNS_2 = "8.8.4.4"
    QUAD_9_DNS = "9.9.9.9"


    # list of all resolvers by supported mode
    # very wordy but eases adding and removal of single servers
    # order implies which is used first
    RESOLVERS: list[DnsResolver] = parse_resolvers([

        # DOH
        (DnsProxyMode.DOH, "Cloudflare 1", CLOUDFLARE_DNS_1, Port.DOH.value),
        (DnsProxyMode.DOH, "Cloudflare 2", CLOUDFLARE_DNS_2, Port.DOH.value),
        (DnsProxyMode.DOH, "Google 1", GOOGLE_DNS_1, Port.DOH.value),
        (DnsProxyMode.DOH, "Google 2", GOOGLE_DNS_2, Port.DOH.value),
        (DnsProxyMode.DOH, "Quad 9", QUAD_9_DNS, Port.DOH.value),

        # DOH3
        (DnsProxyMode.DOH3, "Cloudflare 1", CLOUDFLARE_DNS_1, Port.DOH3.value),
        (DnsProxyMode.DOH3, "Cloudflare 2", CLOUDFLARE_DNS_2, Port.DOH3.value),
        (DnsProxyMode.DOH3, "Google 1", GOOGLE_DNS_1, Port.DOH3.value),
        (DnsProxyMode.DOH3, "Google 2", GOOGLE_DNS_2, Port.DOH3.value),
        (DnsProxyMode.DOH3, "Quad 9", QUAD_9_DNS, Port.DOH3.value),

        # TCP
        (DnsProxyMode.TCP, "Cloudflare 1", CLOUDFLARE_DNS_1, Port.DNS.value),
        (DnsProxyMode.TCP, "Cloudflare 2", CLOUDFLARE_DNS_2, Port.DNS.value),
        (DnsProxyMode.TCP, "Google 1", GOOGLE_DNS_1, Port.DNS.value),
        (DnsProxyMode.TCP, "Google 2", GOOGLE_DNS_2, Port.DNS.value),
        (DnsProxyMode.TCP, "Quad 9", QUAD_9_DNS, Port.DNS.value),

        # DOT
        (DnsProxyMode.DOT, "Cloudflare 1", CLOUDFLARE_DNS_1, Port.DOT.value),
        (DnsProxyMode.DOT, "Cloudflare 2", CLOUDFLARE_DNS_2, Port.DOT.value),
        (DnsProxyMode.DOT, "Google 1", GOOGLE_DNS_1, Port.DOT.value),
        (DnsProxyMode.DOT, "Google 2", GOOGLE_DNS_2, Port.DOT.value),
        (DnsProxyMode.DOT, "Quad 9", QUAD_9_DNS, Port.DOT.value),

        # DOQ
        (DnsProxyMode.DOQ, "Cloudflare 1", CLOUDFLARE_DNS_1, Port.DOQ.value),
        (DnsProxyMode.DOQ, "Cloudflare 2", CLOUDFLARE_DNS_2, Port.DOQ.value),
        (DnsProxyMode.DOQ, "Google 1", GOOGLE_DNS_1, Port.DOQ.value),
        (DnsProxyMode.DOQ, "Google 2", GOOGLE_DNS_2, Port.DOQ.value),
        (DnsProxyMode.DOQ, "Quad 9", QUAD_9_DNS, Port.DOQ.value),

        # UDP
        (DnsProxyMode.UDP, "Cloudflare 1", CLOUDFLARE_DNS_1, Port.DNS.value),
        (DnsProxyMode.UDP, "Cloudflare 2", CLOUDFLARE_DNS_2, Port.DNS.value),
        (DnsProxyMode.UDP, "Google 1", GOOGLE_DNS_1, Port.DNS.value),
        (DnsProxyMode.UDP, "Google 2", GOOGLE_DNS_2, Port.DNS.value),
        (DnsProxyMode.UDP, "Quad 9", QUAD_9_DNS, Port.DNS.value),

        #########################################################
        #                                                       #
        #                                                       #
        #               Add custom DNS servers here             #
        #                                                       #
        #                                                       #
        #########################################################

        # e.g. a DoT server under 127.0.0.1:1234

        # (DnsProxyMode.DOT, "My Server", "127.0.0.1", 1234),

    ])

    def __init__(self, timeout: int):
        self.timeout = timeout


    def determine_mode(self) -> DomainResolver:
        """
        Automatically determines a working circumvention method. Throws an exception if none is found.
        :return: A DomainResolver object configured with working circumvention methods
        """

        # determine all working encrypted DNS modes
        working_encrypted_dns = []
        for encrypted_dns in [DnsProxyMode.DOT, DnsProxyMode.DOQ, DnsProxyMode.DOH, DnsProxyMode.DOH3]:
            working_encrypted_dns += self.determine_encrypted_dns_servers_for_mode(encrypted_dns)
        print("\n".join(map(lambda x:str(x), working_encrypted_dns)))

        # determine all TCP and TCP frag servers
        # TODO: continue here: require a correct hostname and IP combination
        working_tcp = []
        exit()

    def determine_encrypted_dns_servers_for_mode(self, mode: DnsProxyMode) -> list[DnsResolver]:
        """
        Determines all reachable DNS servers that support the given mode.
        :param mode: DnsProxyMode the reachable servers should support. Must be DOQ, DOT, DOH, or DOH3
        """
        _res = []
        # determine correct resolution method
        if mode == DnsProxyMode.DOT:
            _resolve_method = DomainResolver.resolve_dot_static
        elif mode == DnsProxyMode.DOQ:
            _resolve_method = DomainResolver.resolve_doq_static
        elif mode == DnsProxyMode.DOH:
            _resolve_method = DomainResolver.resolve_doh_static
        elif mode == DnsProxyMode.DOH3:
            _resolve_method = DomainResolver.resolve_doh3_static
        else:
            logging.error(f"Mode {mode} not encrypted DNS.")
            return _res

        for resolver in filter(lambda _resolver: _resolver.mode == mode, DnsModeDeterminator.RESOLVERS):
            logging.debug(f"Trying to resolve {resolver.name} for mode {resolver.mode}")
            try:
                _resolve_method(message=DnsModeDeterminator.EXAMPLE_REQUEST, resolver=resolver.address,
                                              timeout=self.timeout)
            except Exception as e:
                logging.debug(f"Could not resolve to {resolver.name} for mode {resolver.mode}")
            else:
                logging.debug(f"Successfully resolved to {resolver.name} for mode {resolver.mode}")
                _res += [resolver]
        return _res
