import socket


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


def is_valid_ipv6_address(ip_address: str) -> bool:
    """
    Returns whether the given string is a valid ipv4 address.
    :param ip_address: String to check for ipv4 validity
    :return: Whether the given string is a valid ip address
    """
    try:
        socket.inet_pton(socket.AF_INET6, ip_address)
        return True
    except socket.error:
        return False


def is_valid_ip_address(ip_address: str) -> bool:
    """
    Returns whether the given string is a valid ip address.
    :param ip_address: String to check for ipv validity
    :return: Whether the given string is a valid ip address
    """
    return is_valid_ipv4_address(ip_address) or is_valid_ipv6_address(ip_address)
