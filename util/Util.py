import socket

from enumerators.NetworkType import NetworkType


def is_valid_ipv4_address(ip_address: str, network_type: NetworkType = NetworkType.DUAL_STACK) -> bool:
    """
    Returns whether the given string is a valid ipv4 address.
    :param ip_address: String to check for ipv4 validity
    :param network_type: Network type to check for
    :return: Whether the given string is a valid ip address
    """
    try:
        socket.inet_aton(ip_address)
        return network_type == NetworkType.IPV4 or network_type == NetworkType.DUAL_STACK
    except socket.error:
        return False


def is_valid_ipv6_address(ip_address: str, network_type: NetworkType = NetworkType.DUAL_STACK) -> bool:
    """
    Returns whether the given string is a valid ipv4 address.
    :param ip_address: String to check for ipv4 validity
    :param network_type: Network type to check for
    :return: Whether the given string is a valid ip address
    """
    try:
        socket.inet_pton(socket.AF_INET6, ip_address)
        return network_type == NetworkType.IPV6 or network_type == NetworkType.DUAL_STACK
    except socket.error:
        return False


def is_valid_ip_address(ip_address: str, network_type: NetworkType = NetworkType.DUAL_STACK) -> bool:
    """
    Returns whether the given string is a valid ip address.
    :param ip_address: String to check for ipv validity
    :param network_type: Network type to check for
    :return: Whether the given string is a valid ip address
    """
    return is_valid_ipv4_address(ip_address, network_type) or is_valid_ipv6_address(ip_address, network_type)
