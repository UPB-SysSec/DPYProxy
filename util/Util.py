import logging
import socket

import dns
from dns.rdatatype import RdataType


def is_valid_ipv4_address(ip_address: str) -> bool:
    """
    Returns whether the given string is a valid ipv4 address.
    :param ip_address: String to check for ipv4 validity
    :return: Whether the given string is a valid ip address
    """
    try:
        socket.inet_aton(ip_address)
        return True
    except socket.error:
        return False

def parse_all_ips(answer: dns.message.Message) -> list[str]:
    resolved_ips = []
    _name = ""
    _rdclass = ""
    _rdtype = ""

    try:
        _name = answer.question[0].name
        _rdclass = answer.question[0].rdclass
        _rdtype = answer.question[0].rdtype

        for record in answer.find_rrset(answer.answer, _name, _rdclass, _rdtype):
            try:
                ip = record.address
                resolved_ips += [ip]
            except Exception as e:
                logging.error(f"Could not extract IP from DNS response with exception {e}:\n{record}")
                continue
    except Exception as e:
        if answer is not None:
            try:
                # Try CNAME backup
                cname = answer.find_rrset(answer.answer, _name, _rdclass, RdataType.CNAME)
                _name = str(cname[0])

                for record in answer.find_rrset(answer.answer, _name, _rdclass, _rdtype):
                    try:
                        ip = record.address
                        resolved_ips += [ip]
                    except Exception as e:
                        logging.error(f"Could not extract IP from DNS response with exception {e}:\n{record}")
                        continue
            except Exception as e:
                logging.error(
                f"Could not extract IP from DNS response with exception {e}:\n{_name}, {_rdclass}, {_rdtype}; {answer.answer}")
        else:
            logging.error(
                f"Could not extract IP from DNS response with exception {e}:\n{_name}, {_rdclass}, {_rdtype}; None")
    return resolved_ips