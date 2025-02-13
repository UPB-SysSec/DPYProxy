from enum import Enum

class DnsResolvers(Enum):
    """
    Ip addresses of public DNS resolvers.
    """

    # Initial list https://en.wikipedia.org/wiki/Public_recursive_name_server

    # Adguard https://adguard-dns.io/en/public-dns.html
    ADGUARD_1 = "94.140.14.14"
    ADGUARD_2 = "94.140.15.15"
    ADGUARD_FAMILY_1 = "94.140.14.15"
    ADGUARD_FAMILY_2 = "94.140.15.16"
    ADGUARD_UNFILTERED_1 = "94.140.14.140"
    ADGUARD_UNFILTERED_2 = "94.140.14.141"

    # CleanBrowsing https://cleanbrowsing.org/filters
    CLEAN_BROWSING_FAMILY_1 = "185.228.168.168"
    CLEAN_BROWSING_FAMILY_2 = "185.228.169.168"
    CLEAN_BROWSING_UNFILTERED_1 = "185.228.168.10"
    CLEAN_BROWSING_UNFILTERED_2 = "185.228.169.11"
    CLEAN_BROWSING_SECURITY_1 = "185.228.168.9"
    CLEAN_BROWSING_SECURITY_2 = "185.228.169.9"

    # Cloudflare https://developers.cloudflare.com/1.1.1.1/ip-addresses/
    CLOUDFLARE_1 = "1.1.1.1"
    CLOUDFLARE_2 = "1.0.0.1"
    CLOUDFLARE_SECURITY_1 = "1.1.1.2"
    CLOUDFLARE_SECURITY_2 = "1.0.0.2"
    CLOUDFLARE_FAMILY_1 = "1.1.1.3"
    CLOUDFLARE_FAMILY_2 = "1.0.0.3"

    # https://developers.google.com/speed/public-dns
    GOOGLE_1 = "8.8.8.8"
    GOOGLE_2 = "8.8.4.4"

    # Gcore https://gcore.com/public-dns
    G_CORE_1 = "95.85.95.85"
    G_CORE_2 = "2.56.220.2"

    # Mullvad https://mullvad.net/en/help/dns-over-https-and-dns-over-tls
    MULLVAD = "194.242.2.2"
    MULLVAD_ADBLOCK = "194.242.2.3"
    MULLVAD_BASE = "194.242.2.4"
    MULLVAD_EXTENDED = "194.242.2.5"
    MULLVAD_FAMILY = "194.242.2.6"
    MULLVAD_ALL = "194.242.2.9"

    # Cisco https://umbrella.cisco.com/blog/enhancing-support-dns-encryption-with-dns-over-https
    CISCO_1 = "208.67.222.222"
    CISCO_2 = "208.67.220.220"
    CISCO_FAMILY_1 = "208.67.222.123"
    CISCO_FAMILY_2 = "208.67.220.123"
    CISCO_SANDBOX_1 = "208.67.222.2"
    CISCO_SANDBOX_2 = "208.67.220.2"

    # Quad 9 https://www.quad9.net/support/faq/
    QUAD_9_1 = "9.9.9.9"
    QUAD_9_2 = "149.112.112.112"
    QUAD_9_EDNS_1 = "9.9.9.11"
    QUAD_9_EDNS_2 = "149.112.112.11"
    QUAD_9_UNSECURED_1 = "9.9.9.10"
    QUAD_9_UNSECURED_2 = "149.112.112.10"

    # wikimedia https://meta.wikimedia.org/wiki/Wikimedia_DNS
    WIKIMEDIA = "185.71.138.138"

    # Yandex https://dns.yandex.com/
    YANDEX_1 = "77.88.8.8"
    YANDEX_2 = "77.88.8.1"
    YANDEX_SAFE_1 = "77.88.8.88"
    YANDEX_SAFE_2 = "77.88.8.2"
    YANDEX_FAMILY_1 = "77.88.8.7"
    YANDEX_FAMILY_2 = "77.88.8.3"

    # TODO: add vercara and oracle?

    def is_default(self):
        """
        Returns true if we consider the DNS server to be default. DpyProxy favors "default" DNS resolvers in its AUTO
        selection mode.
        """
        return self in [DnsResolvers.ADGUARD_UNFILTERED_1,
                        DnsResolvers.ADGUARD_UNFILTERED_2,
                        DnsResolvers.CLEAN_BROWSING_UNFILTERED_1,
                        DnsResolvers.CLEAN_BROWSING_UNFILTERED_2,
                        DnsResolvers.CLOUDFLARE_1,
                        DnsResolvers.CLOUDFLARE_2,
                        DnsResolvers.GOOGLE_1,
                        DnsResolvers.GOOGLE_2,
                        DnsResolvers.G_CORE_1,
                        DnsResolvers.G_CORE_2,
                        DnsResolvers.MULLVAD,
                        DnsResolvers.CISCO_1,
                        DnsResolvers.CISCO_2,
                        DnsResolvers.QUAD_9_UNSECURED_1,
                        DnsResolvers.QUAD_9_UNSECURED_2,
                        DnsResolvers.YANDEX_1,
                        DnsResolvers.YANDEX_2]

    def is_family(self):
        """
        Returns true if the resolver filters content it considers adult. DpyProxy favors resolvers that do not apply
        family filters in its AUTO selection mode.
        """
        return self in [DnsResolvers.ADGUARD_FAMILY_1,
                        DnsResolvers.ADGUARD_FAMILY_2,
                        DnsResolvers.CLEAN_BROWSING_FAMILY_1,
                        DnsResolvers.CLEAN_BROWSING_FAMILY_1,
                        DnsResolvers.CLOUDFLARE_FAMILY_1,
                        DnsResolvers.CLOUDFLARE_FAMILY_2,
                        DnsResolvers.MULLVAD_FAMILY,
                        DnsResolvers.MULLVAD_ALL,
                        DnsResolvers.CISCO_FAMILY_1,
                        DnsResolvers.CISCO_FAMILY_2,
                        DnsResolvers.YANDEX_FAMILY_1,
                        DnsResolvers.YANDEX_FAMILY_2]