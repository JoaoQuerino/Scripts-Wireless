import socket
import psutil

def get_all_ips():
    ip_list = []
    for i in psutil.net_if_addrs().values():
        for j in i:
            if j.family == socket.AF_INET:
                ip_list.append(j.address)
    return ip_list

def check_ipv4(IP):
    model = r'^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$'
    if not bool(re.match(model, IP)):
        return False

    parts = IP.split('.')
    if len(parts) == 5:
        mask = int(parts[4])
        if not (0 <= mask <= 32):
            return False

    return all(0 <= int(part) < 256 for part in parts[:3])