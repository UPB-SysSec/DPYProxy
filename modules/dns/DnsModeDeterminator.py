import logging
from ipaddress import ip_network, ip_address

import dns.message

from enumerators.DnsProxyMode import DnsProxyMode
from enumerators.DnsResolvers import DnsResolvers
from modules.dns.DnsResolver import DnsResolver
from network.DomainResolver import DomainResolver
from network.NetworkAddress import NetworkAddress

from dns.message import make_query


class DnsModeDeterminator:
    """
    Determines functioning circumvention modes and reachable DoQ/DoH/etc. servers.
    """

    @staticmethod
    def parse_custom_resolvers(resolvers: list[tuple[DnsProxyMode, str, str, int, str]]) -> list[DnsResolver]:
        """
        Parses a list of custom resolvers (tuple of ProxyMode, name, ip, port) into DnsResolver objects.
        """
        _ret = []
        for resolver in resolvers:
            address = NetworkAddress(resolver[2], resolver[3])
            _ret += [DnsResolver(resolver[1], address, resolver[0], resolver[4])]
        return _ret

    @staticmethod
    def parse_default_resolvers(resolvers: list[DnsResolvers], modes: list[DnsProxyMode]) -> list[DnsResolver]:
        """
        Parses a list of default resolvers into DnsResolver objects using their standard ports and names. Does that for
        all provided proxy modes.
        """
        _ret = []
        for mode in modes:
            # call custom resolver method with resolvers default values
           _ret += DnsModeDeterminator.parse_custom_resolvers(
                list(map(
                    lambda resolver: (mode, str(resolver.name), str(resolver.value), mode.default_port(), str(resolver.hostname)), resolvers)))
        return _ret

    @staticmethod
    def generate_resolvers() -> list[DnsResolver]:
        """
        Generates a list of DnsResolver objects based on the statically defined addresses below.
        """
        _res = []

        # append RESOLVERS_SUPPORT_ALL
        _res += DnsModeDeterminator.parse_default_resolvers(DnsModeDeterminator.RESOLVERS_SUPPORT_ALL,
                                                            [mode for mode in DnsProxyMode if mode != DnsProxyMode.AUTO])

        # append RESOLVERS_SUPPORT_ALL_EXCEPT_DOQ
        _res += DnsModeDeterminator.parse_default_resolvers(DnsModeDeterminator.RESOLVERS_SUPPORT_ALL_EXCEPT_DOQ,
                                                            [mode for mode in DnsProxyMode if mode != DnsProxyMode.DOQ and mode != DnsProxyMode.AUTO])

        # append RESOLVERS_SUPPORT_ENCRYPTED_EXCEPT_DOQ
        _res += DnsModeDeterminator.parse_default_resolvers(DnsModeDeterminator.RESOLVERS_SUPPORT_ENCRYPTED_EXCEPT_DOQ,
                                                            [DnsProxyMode.DOT, DnsProxyMode.DOH, DnsProxyMode.DOH3])

        # append RESOLVERS_SUPPORT_ONLY_UNENCRYPTED
        _res += DnsModeDeterminator.parse_default_resolvers(DnsModeDeterminator.RESOLVERS_SUPPORT_ONLY_UNENCRYPTED,
                                                            [DnsProxyMode.UDP,
                                                             DnsProxyMode.TCP,
                                                             DnsProxyMode.TCP_FRAG,
                                                             DnsProxyMode.LAST_RESPONSE])
        return _res

    # TODO: refine these lists based on what servers actually support

    # resolvers that support UDP/TPC/DoT/DoH/DoH3/DoQ
    RESOLVERS_SUPPORT_ALL: list[DnsResolvers] = [DnsResolvers.ADGUARD_1,
                                                 DnsResolvers.ADGUARD_2,
                                                 DnsResolvers.ADGUARD_UNFILTERED_1,
                                                 DnsResolvers.ADGUARD_UNFILTERED_2,
                                                 DnsResolvers.ADGUARD_FAMILY_1,
                                                 DnsResolvers.ADGUARD_FAMILY_2]

    # resolvers that support UDP/TCP/DoT/DoH/DoH3 but no DoQ
    RESOLVERS_SUPPORT_ALL_EXCEPT_DOQ: list[DnsResolvers] = [DnsResolvers.CLEAN_BROWSING_FAMILY_1,
                                                            DnsResolvers.CLEAN_BROWSING_FAMILY_2,
                                                            DnsResolvers.CLEAN_BROWSING_UNFILTERED_1,
                                                            DnsResolvers.CLEAN_BROWSING_UNFILTERED_2,
                                                            DnsResolvers.CLEAN_BROWSING_SECURITY_1,
                                                            DnsResolvers.CLEAN_BROWSING_SECURITY_2,
                                                            DnsResolvers.CLOUDFLARE_1,
                                                            DnsResolvers.CLOUDFLARE_2,
                                                            DnsResolvers.CLOUDFLARE_SECURITY_1,
                                                            DnsResolvers.CLOUDFLARE_SECURITY_2,
                                                            DnsResolvers.CLOUDFLARE_FAMILY_1,
                                                            DnsResolvers.CLOUDFLARE_FAMILY_2,
                                                            DnsResolvers.GOOGLE_1,
                                                            DnsResolvers.GOOGLE_2,
                                                            DnsResolvers.CISCO_1,
                                                            DnsResolvers.CISCO_2,
                                                            DnsResolvers.CISCO_FAMILY_1,
                                                            DnsResolvers.CISCO_FAMILY_2,
                                                            DnsResolvers.CISCO_SANDBOX_1,
                                                            DnsResolvers.CISCO_SANDBOX_2,
                                                            DnsResolvers.QUAD_9_1,
                                                            DnsResolvers.QUAD_9_2,
                                                            DnsResolvers.QUAD_9_EDNS_1,
                                                            DnsResolvers.QUAD_9_EDNS_2,
                                                            DnsResolvers.QUAD_9_UNSECURED_1,
                                                            DnsResolvers.QUAD_9_UNSECURED_2,
                                                            DnsResolvers.YANDEX_1,
                                                            DnsResolvers.YANDEX_2,
                                                            DnsResolvers.YANDEX_SAFE_1,
                                                            DnsResolvers.YANDEX_SAFE_2,
                                                            DnsResolvers.YANDEX_FAMILY_1,
                                                            DnsResolvers.YANDEX_FAMILY_2]

    # resolvers that support DoT/DoH/DoH3
    RESOLVERS_SUPPORT_ENCRYPTED_EXCEPT_DOQ: list[DnsResolvers] = [DnsResolvers.WIKIMEDIA,
                                                                  DnsResolvers.MULLVAD,
                                                                  DnsResolvers.MULLVAD_ADBLOCK,
                                                                  DnsResolvers.MULLVAD_BASE,
                                                                  DnsResolvers.MULLVAD_EXTENDED,
                                                                  DnsResolvers.MULLVAD_FAMILY,
                                                                  DnsResolvers.MULLVAD_ALL]

    # resolvers that support UDP/TCP
    RESOLVERS_SUPPORT_ONLY_UNENCRYPTED: list[DnsResolvers] = [DnsResolvers.G_CORE_1,
                                                              DnsResolvers.G_CORE_2]

    CUSTOM_RESOLVERS: list[DnsResolver] = parse_custom_resolvers([

        #########################################################
        #                                                       #
        #                                                       #
        #               Add custom DNS servers here             #
        #                                                       #
        #                                                       #
        #########################################################

        # each server need the supported proxy mode, a name, the IP address, and a port

        # e.g. a DoT server under 127.0.0.1:1234
        # (DnsProxyMode.DOT, "My Server", "127.0.0.1", 1234),

    ])

    def __init__(self, timeout: int, censored_domain: str, censored_domain_ip_ranges: list[str]):
        """
        :param timeout: timeout for DNS requests
        :param censored_domain: censored domain
        :param censored_domain_ip_ranges: ip ranges of the censored domain. An IP returned by a DNS resolver must lie
        in one of these ranges to be deemed correct
        """

        self.timeout = timeout
        self.censored_domain = censored_domain

        self.censored_domain_ip_ranges = []
        for ip_range in censored_domain_ip_ranges:
            try:
                self.censored_domain_ip_ranges.append(ip_network(ip_range))
            except:
                logging.error(f"Could not parse {ip_range} as a valid ip range!")
                raise
        self.censored_request = make_query(censored_domain, "A")
        self.resolvers: list[DnsResolver] = DnsModeDeterminator.generate_resolvers()

    def generate_working_resolver(self, mode: DnsProxyMode = None, retries: int = 5):
        """
        Generator that yields all working DnsResolvers.
        :param mode: Restricts resolver generation to the specified mode.
        :param retries: Number of retries to determine success by majority voting
        """
        for _mode in [DnsProxyMode.DOT, DnsProxyMode.DOH, DnsProxyMode.DOH3, DnsProxyMode.DOQ]:
            if mode is None or mode == _mode:
                yield from self.generate_resolvers_supporting_mode(mode=_mode, validate_ip=False, retries = retries)
        for _mode in [DnsProxyMode.UDP, DnsProxyMode.TCP, DnsProxyMode.TCP_FRAG, DnsProxyMode.LAST_RESPONSE]:
            if mode is None or mode == _mode:
                yield from self.generate_resolvers_supporting_mode(mode=_mode, validate_ip=True, retries = retries)


    def generate_resolvers_supporting_mode(self, mode: DnsProxyMode, validate_ip: bool, retries: int = 5):
        """
        Generator function that determines all reachable DNS resolvers for the specified mode. If validate_ip is True, the DNS resolver must respond with a pre-defined IP address.
        """
        for resolver in filter(lambda _resolver: _resolver.mode == mode, self.resolvers):
            logging.debug(f"Trying to resolve {resolver.name} for mode {resolver.mode}")
            working_count = 0
            for i in range(retries):
                try:
                    answer = DomainResolver.resolve_static(mode=mode, message=self.censored_request, resolver=resolver.address, timeout=self.timeout, hostname=resolver.hostname)
                except Exception as e:
                    logging.debug(f"Could not resolve to {resolver.name} for mode {resolver.mode} with exception {e}")
                else:
                    if validate_ip:
                        if self.assert_correct_ip(answer):
                            logging.debug(f"Successfully resolved to {resolver.name} for mode {resolver.mode}")
                            working_count += 1
                        else:
                            print(f"Could not resolve to {resolver.name} for mode {resolver.mode}")
                    else:
                        logging.debug(f"Successfully resolved to {resolver.name} for mode {resolver.mode}")
                        working_count += 1
            if working_count > retries / 2:
                yield resolver

    def assert_correct_ip(self, answer: dns.message.Message) -> bool:
        """
        Determines whether the given DNS response contains the given IP in its answer section.
        :param answer: The DNS response to check.
        """
        # extract requires record type and class
        _name = answer.question[0].name
        _rdclass = answer.question[0].rdclass
        _rdtype = answer.question[0].rdtype
        resolved_ips = []

        for record in answer.find_rrset(answer.answer, _name, _rdclass, _rdtype):
            try:
                ip = record.address
                resolved_ips += [ip]
            except Exception as e:
                logging.error(f"Could not extract IP from DNS response with exception {e}:\n{record}")
                continue
            else:
                # check if IP lies in range
                for ip_range in self.censored_domain_ip_ranges:
                    if ip_address(ip) in ip_range:
                        return True
        logging.debug(f"None of the resolved IP addresses {resolved_ips} in specified IP ranges {self.censored_domain_ip_ranges}.")
        return False