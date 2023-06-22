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
