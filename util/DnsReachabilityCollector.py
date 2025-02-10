# Determines and outputs the reachability of all DNS servers and circumvention methods's specified in DnsModeDeterminator.py
import logging

from modules.dns.DnsModeDeterminator import DnsModeDeterminator

TIMEOUT = 5
CENSORED_DOMAIN = "wikipedia.org"
CENSORED_DOMAIN_IP = "185.15.59.224"

def main():
    _det = DnsModeDeterminator(timeout=TIMEOUT,
                        censored_domain=CENSORED_DOMAIN,
                        censored_domain_ip=CENSORED_DOMAIN_IP)

    logging.info("Generating working resolvers... might take a while!")
    for mode in [x for x in _det.generate_working_resolver()]:
        print(mode)


if __name__ == "__main__":
    main()