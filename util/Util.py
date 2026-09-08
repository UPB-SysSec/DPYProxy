import argparse
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
        socket.inet_pton(socket.AF_INET, ip_address)
        return True
    except socket.error:
        return False


def is_valid_ipv6_address(ip_address: str) -> bool:
    """
    Returns whether the given string is a valid ipv6 address.
    :param ip_address: String to check for ipv6 validity
    :return: Whether the given string is a valid ip address
    """
    try:
        socket.inet_pton(socket.AF_INET6, ip_address)
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
                    f"Could not extract IP from DNS response with exception {e}:\n{_name}, {_rdclass}, {_rdtype}; "
                    f"{answer.answer}"
                )
        else:
            logging.error(
                f"Could not extract IP from DNS response with exception {e}:\n{_name}, {_rdclass}, {_rdtype}; None"
            )
    return resolved_ips


def port_range(value):
    try:
        ivalue = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value} is an invalid port. Must be a number between 1 and 65535.")
    if ivalue < 1 or ivalue > 65535:
        raise argparse.ArgumentTypeError(f"{value} is an invalid port. Must be between 1 and 65535.")
    return ivalue
