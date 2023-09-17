import socket
import psutil
import re
from printer import f_print, formater_text, FontTypes


def check_interface(interface_to_check) -> bool:
    interface_availabre = psutil.net_if_addrs().keys()
    
    if interface_to_check in interface_availabre:
        return True
    else:
        return False

def get_all_ips():
    """
    Returns a list containing all available IPv4 addresses on the network interfaces of the system.

    This function utilizes the `psutil` library to retrieve information about network interfaces and their
    associated IP addresses. It iterates through all address information associated with the interfaces and
    filters those with an address family of AF_INET (IPv4). IPv4 addresses are extracted and added to a list,
    which is then returned as the result.

    Returns:
        list: A list containing the IPv4 addresses of the network interfaces.

    Example:
        >>> get_all_ips()
        ['192.168.1.2', '10.0.0.1']
    """
    ip_list = []
    for i in psutil.net_if_addrs().values():
        for j in i:
            if j.family == socket.AF_INET:
                ip_list.append(j.address)
    return ip_list

def input_ipv4_re() -> str:
    """
    Function to prompt the user for an IPv4 address and validate it.
    
    Returns:
        str: The valid IPv4 address entered by the user.
        
    Raises:
        TypeError: If the entered IP address is not in the correct format or has an invalid subnet mask.
    """
    while True:
        ip = input('Insert the IPv4: ')
        if ip != '':
            pattern = r'^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$'
            if not bool(re.match(pattern, ip)):
                f_print(formater_text('Invalid IPv4 address format.', FontTypes.ERROR))
                continue

            parts = ip.split('.')
            if len(parts) == 4 and '/' not in parts[3]:
                return ip

            last_part = parts[3].split('/')
            parts.append(last_part[0])
            cidr = int(last_part[1])

            if not (0 <= cidr <= 32):
                f_print(formater_text('Invalid subnet mask.', FontTypes.ERROR))
                continue
            if all(0 <= int(part) < 256 for part in parts[:3]):
                print(ip)
                return ip