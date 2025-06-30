from enum import Enum

class DnsResolvers(Enum):
    """
    Ip addresses of public DNS resolvers.
    """

    # Initial list https://en.wikipedia.org/wiki/Public_recursive_name_server

    # Adguard https://adguard-dns.io/en/public-dns.html
    ADGUARD_1 = ("94.140.14.14", "dns.adguard-dns.com", "/dns-query")
    ADGUARD_2 = ("94.140.15.15", "dns.adguard-dns.com", "/dns-query")
    ADGUARD_FAMILY_1 = ("94.140.14.15", "family.adguard-dns.com", "/dns-query")
    ADGUARD_FAMILY_2 = ("94.140.15.16", "family.adguard-dns.com", "/dns-query")
    ADGUARD_UNFILTERED_1 = ("94.140.14.140", "unfiltered.adguard-dns.com", "/dns-query")
    ADGUARD_UNFILTERED_2 = ("94.140.14.141", "unfiltered.adguard-dns.com", "/dns-query")

    # CleanBrowsing https://cleanbrowsing.org/filters
    CLEAN_BROWSING_FAMILY_1 = ("185.228.168.168", "family-filter-dns.cleanbrowsing.org", "/doh/family-filter/")
    CLEAN_BROWSING_FAMILY_2 = ("185.228.169.168", "family-filter-dns.cleanbrowsing.org", "/doh/family-filter/")
    CLEAN_BROWSING_ADULT_1 = ("185.228.168.10", "adult-filter-dns.cleanbrowsing.org", "/doh/adult-filter/")
    CLEAN_BROWSING_ADULT_2 = ("185.228.169.11", "adult-filter-dns.cleanbrowsing.org", "/doh/adult-filter/")
    CLEAN_BROWSING_SECURITY_1 = ("185.228.168.9", "security-filter-dns.cleanbrowsing.org", "/doh/security-filter/")
    CLEAN_BROWSING_SECURITY_2 = ("185.228.169.9", "security-filter-dns.cleanbrowsing.org", "/doh/security-filter/")

    # Cloudflare https://developers.cloudflare.com/1.1.1.1/ip-addresses/
    CLOUDFLARE_1 = ("1.1.1.1", "one.one.one.one", "/dns-query")
    CLOUDFLARE_2 = ("1.0.0.1", "1dot1dot1dot1.cloudflare-dns.com", "/dns-query")
    CLOUDFLARE_SECURITY_1 = ("1.1.1.2", "security.cloudflare-dns.com", "/dns-query")
    CLOUDFLARE_SECURITY_2 = ("1.0.0.2", "security.cloudflare-dns.com", "/dns-query")
    CLOUDFLARE_FAMILY_1 = ("1.1.1.3", "family.cloudflare-dns.com", "/dns-query")
    CLOUDFLARE_FAMILY_2 = ("1.0.0.3", "family.cloudflare-dns.com", "/dns-query")
    CLOUDFLARE_MOZILLA_1 = ("162.159.61.4", "mozilla.cloudflare-dns.com", "/dns-query")
    CLOUDFLARE_MOZILLA_2 = ("172.64.41.4", "mozilla.cloudflare-dns.com", "/dns-query")
    CLOUDFLARE_CHROMIUM_1 = ("172.64.41.3", "chrome.cloudflare-dns.com", "/dns-query")
    CLOUDFLARE_CHROMIUM_2 = ("162.159.61.3", "chrome.cloudflare-dns.com", "/dns-query")

    # https://developers.google.com/speed/public-dns
    GOOGLE_1 = ("8.8.8.8", "dns.google", "/dns-query")
    GOOGLE_2 = ("8.8.4.4", "dns.google", "/dns-query")

    # Gcore https://gcore.com/public-dns
    G_CORE_1 = ("95.85.95.85", "", "/dns-query")
    G_CORE_2 = ("2.56.220.2", "", "/dns-query")

    # Mullvad https://mullvad.net/en/help/dns-over-https-and-dns-over-tls
    MULLVAD = ("194.242.2.2", "dns.mullvad.net", "/dns-query")
    MULLVAD_ADBLOCK = ("194.242.2.3", "adblock.dns.mullvad.net", "/dns-query")
    MULLVAD_BASE = ("194.242.2.4", "base.dns.mullvad.net", "/dns-query")
    MULLVAD_EXTENDED = ("194.242.2.5", "extended.dns.mullvad.net", "/dns-query")
    MULLVAD_FAMILY = ("194.242.2.6", "family.dns.mullvad.net", "/dns-query")
    MULLVAD_ALL = ("194.242.2.9", "all.dns.mullvad.net", "/dns-query")

    # Cisco https://umbrella.cisco.com/blog/enhancing-support-dns-encryption-with-dns-over-https
    CISCO_1 = ("208.67.222.222", "dns.opendns.com", "/dns-query")
    CISCO_2 = ("208.67.220.220", "dns.umbrella.com", "/dns-query")
    CISCO_FAMILY_1 = ("208.67.222.123", "familyshield.opendns.com", "/dns-query")
    CISCO_FAMILY_2 = ("208.67.220.123", "familyshield.opendns.com", "/dns-query")
    CISCO_SANDBOX_1 = ("208.67.222.2", "sandbox.opendns.com", "/dns-query")
    CISCO_SANDBOX_2 = ("208.67.220.2", "sandbox.opendns.com", "/dns-query")
    CISCO_CHROMIUM = ("146.112.41.2", "doh.opendns.com", "/dns-query")

    # Quad 9 https://www.quad9.net/support/faq/
    QUAD_9_1 = ("9.9.9.9", "dns.quad9.net", "/dns-query")
    QUAD_9_2 = ("149.112.112.112", "dns.quad9.net", "/dns-query")
    QUAD_9_EDNS_1 = ("9.9.9.11", "dns11.quad9.net", "/dns-query")
    QUAD_9_EDNS_2 = ("149.112.112.11", "dns11.quad9.net", "/dns-query")
    QUAD_9_UNSECURED_1 = ("9.9.9.10", "dns10.quad9.net", "/dns-query")
    QUAD_9_UNSECURED_2 = ("149.112.112.10", "dns10.quad9.net", "/dns-query")

    # wikimedia https://meta.wikimedia.org/wiki/Wikimedia_DNS
    WIKIMEDIA = ("185.71.138.138", "wikimedia-dns.org", "/dns-query")

    # Yandex https://dns.yandex.com/
    YANDEX_1 = ("77.88.8.8", "common.dot.dns.yandex.net", "/dns-query")
    YANDEX_2 = ("77.88.8.1", "common.dot.dns.yandex.net", "/dns-query")
    YANDEX_SAFE_1 = ("77.88.8.88", "safe.dot.dns.yandex.net", "/dns-query")
    YANDEX_SAFE_2 = ("77.88.8.2", "safe.dot.dns.yandex.net", "/dns-query")
    YANDEX_FAMILY_1 = ("77.88.8.7", "family.dot.dns.yandex.net", "/dns-query")
    YANDEX_FAMILY_2 = ("77.88.8.3", "family.dot.dns.yandex.net", "/dns-query")

    # NextDNS https://nextdns.io/ Firefox and Chromium use both
    NEXTDNS_1 = ("194.45.101.249", "dns.nextdns.io", "/dns-query")
    NEXTDNS_2 = ("217.146.22.163", "dns.nextdns.io", "/dns-query")

    def __new__(cls, ip, hostname, path):
        obj = object.__new__(cls)
        obj._value_ = ip  # The actual enum value is the IP address
        obj.hostname = hostname  # Store hostname
        obj.path = path # Store path
        return obj

    def __str__(self):
        return f"{self.name} ({self.value}): {self.hostname}"

    def is_default(self):
        """
        Returns true if we consider the DNS server to be default. DpyProxy favors "default" DNS resolvers in its AUTO
        selection mode.
        """
        return self in [DnsResolvers.ADGUARD_UNFILTERED_1,
                        DnsResolvers.ADGUARD_UNFILTERED_2,
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
                        DnsResolvers.YANDEX_2,
                        DnsResolvers.NEXTDNS_1,
                        DnsResolvers.NEXTDNS_2,
                        DnsResolvers.CISCO_CHROMIUM]

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