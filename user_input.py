import ipaddress
from printer import FontTypes, formater_text, f_print, f_input
from enum import Enum


class Protocol(Enum):
    """
    Enumeration of supported protocols.

    TCP: TCP protocol.
    UDP: UDP protocol.
    ICMP: ICMP protocol.
    """

    TCP = 0
    UDP = 1
    ICMP = 2


class SendMode(Enum):
    """
    Enumeration of supported send modes.

    EXPONENTIAL: Exponential growth send mode.
    SINGLE: Single batch send mode.
    OVERLOAD: Traffic overload send mode.
    """

    EXPONENTIAL = 0
    SINGLE = 1
    OVERLOAD = 2


def choose_send_mode() -> SendMode:
    """
    Prompts for input of a supported send mode until one is entered.
    Returns the supported send mode entered as a SendMode Enum.
    """

    supported_send_modes = [sm.name for sm in SendMode]
    supported_send_modes_str = ', '.join([formater_text(s, FontTypes.BOLD) for s in supported_send_modes])
    send_mode = f_input(f'{formater_text("Select a supported send mode", FontTypes.NORMAL)} ({supported_send_modes_str}): ').upper()

    while send_mode not in supported_send_modes:
        if send_mode:
            f_print(formater_text(f'{send_mode} is not a supported send mode.'), FontTypes.ERROR)
        send_mode = f_input(f'{formater_text("Select a supported send mode", FontTypes.NORMAL)} ({supported_send_modes_str}): ').upper()

    return SendMode(supported_send_modes.index(send_mode))

def choose_protocol() -> Protocol:
    """
    Prompts for input of a supported protocol until one is entered.
    Returns the supported protocol entered as a Protocol Enum.
    """

    supported_protocols = [p.name for p in Protocol]
    supported_protocols_str = ', '.join([formater_text(p, FontTypes.BOLD) for p in supported_protocols])
    protocol = f_input(f'{formater_text("Select a supported packet type", FontTypes.NORMAL)} ({supported_protocols_str}): ').upper()

    while protocol not in supported_protocols:
        if protocol != '':
            f_print(formater_text(f'{protocol} is not a supported protocol.', FontTypes.ERROR))

        protocol = f_input(f'{formater_text("Select a supported packet type", FontTypes.NORMAL)} ({supported_protocols_str}): ').upper()

    return Protocol(supported_protocols.index(protocol))

def host_ip_input() -> str: 
        """
        Prompts the user to enter the IP address of the destination host.

        :return: The entered host IP address.
        """
        # TODO: Dar a opçao de listar ip dos aparelhos na rede para selecionar - Usar PortScanner

        valid = False
        while valid == False:
            try:
                host_ip = f_input(formater_text('Enter the IP address of the destination host: ', FontTypes.NORMAL))
                if ipaddress.IPv4Address(host_ip):
                    valid = True
            except ipaddress.AddressValueError:
                f_print(formater_text('Invalid ipv4 address value', FontTypes.ERROR))
            except Exception as e:
                f_print(formater_text(str(e), FontTypes.ERROR))
        return host_ip

def host_port_input(host_ip) -> str: 
        """
        Prompts the user to enter the destination port.

        :param host_ip: The IP address of the destination host.
        :return: The entered destination port.
        """
        # TODO: Dar a opcao de listar portas abertas para selecionar - Usar PortScanner

        valid = False
        while valid == False:
            try:
                host_port = int(f_input(formater_text('Enter the destination port: ', FontTypes.NORMAL)))
                valid = True
            except ValueError:
                f_print(formater_text('The port has to be an integer', FontTypes.ERROR))
            except Exception as e:
                f_print(formater_text(str(e), FontTypes.ERROR))

        return host_port

def payload_input() -> str:
    """
    Prompts the user to enter a payload for the packet.

    :return: The entered payload.
    """

    payload = f_input(formater_text('Enter a payload to be in the package: ', FontTypes.NORMAL))

    return payload

