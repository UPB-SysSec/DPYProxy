from enumerators.DnsProxyMode import DnsProxyMode
from enumerators.Port import Port
from modules.dns.DnsProxy import DnsProxy
from modules.dns.DnsResolver import DnsResolver
from network.NetworkAddress import NetworkAddress


class DnsModeDeterminator:

    # extend with https://en.wikipedia.org/wiki/Public_recursive_name_server

    # TODO adguard
    # TODO cloudflare family and security?
    # TODO mullvad
    # TODO cisco umberalla?
    # TODO quad 9 backups ?
    # TODO yandex

    @staticmethod
    def parse_resolvers(resolvers:list[tuple[DnsProxyMode, str, str, int]]) -> list[DnsResolver]:
        _ret = []
        for resolver in resolvers:
            address = NetworkAddress(resolver[2], resolver[3])
            _ret += [DnsResolver(resolver[1], address, resolver[0])]
        return _ret

    CLOUDFLARE_DNS_1 = "1.1.1.1"
    CLOUDFLARE_DNS_2 = "1.0.0.1"
    GOOGLE_DNS_1 = "8.8.8.8"
    GOOGLE_DNS_2 = "8.8.4.4"
    QUAD_9_DNS = "9.9.9.9"

    # list of all resolvers by supported mode
    # very wordy but eases adding and removal of single servers
    RESOLVERS: list[DnsResolver] = parse_resolvers([

        # UDP
        (DnsProxyMode.UDP, "Cloudflare 1", CLOUDFLARE_DNS_1, Port.DNS.value),
        (DnsProxyMode.UDP, "Cloudflare 2", CLOUDFLARE_DNS_2, Port.DNS.value),
        (DnsProxyMode.UDP, "Google 1", GOOGLE_DNS_1, Port.DNS.value),
        (DnsProxyMode.UDP, "Google 2", GOOGLE_DNS_2, Port.DNS.value),
        (DnsProxyMode.UDP, "Quad 9", QUAD_9_DNS, Port.DNS.value),

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

        # DOH
        (DnsProxyMode.DOT, "Cloudflare 1", CLOUDFLARE_DNS_1, Port.DOH.value),
        (DnsProxyMode.DOT, "Cloudflare 2", CLOUDFLARE_DNS_2, Port.DOH.value),
        (DnsProxyMode.DOT, "Google 1", GOOGLE_DNS_1, Port.DOH.value),
        (DnsProxyMode.DOT, "Google 2", GOOGLE_DNS_2, Port.DOH.value),
        (DnsProxyMode.DOT, "Quad 9", QUAD_9_DNS, Port.DOH.value),

        # DOQ
        # TODO: who supports this and fix DoQ / DoH3 difference in code
        (DnsProxyMode.DOT, "Cloudflare 1", CLOUDFLARE_DNS_1, Port.DOQ.value),
        (DnsProxyMode.DOT, "Cloudflare 2", CLOUDFLARE_DNS_2, Port.DOQ.value),
        (DnsProxyMode.DOT, "Google 1", GOOGLE_DNS_1, Port.DOQ.value),
        (DnsProxyMode.DOT, "Google 2", GOOGLE_DNS_2, Port.DOQ.value),
        (DnsProxyMode.DOT, "Quad 9", QUAD_9_DNS, Port.DOQ.value),

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


    def determine_mode(self, dns_proxy: DnsProxy):
        """
        Automatically determines a working circumvention method. Throws an exception if none is found. Applies the mode
        and working DoT/DoQ/etc. server directly to DnsProxy
        """
        # TODO: try all DoT etc servers
        # TODO: attempt to access censored website and ip using TCP, TCP_FRAG and LAST_RESPONSE
        pass

    def determine_dot_servers(self) -> list[DnsResolver]:
        _res = []
        for resolver in filter(lambda _resolver: _resolver.mode == DnsProxyMode.DOT, DnsModeDeterminator.RESOLVERS):



    def determine_doh_servers(self) -> list[DnsResolver]:
        pass

    def determine_doq_servers(self) -> list[DnsResolver]:
        pass