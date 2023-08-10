import ipaddress
from printer import FontTypes, formater_text, f_print, f_input
from enum import Enum
from common import input_ipv4_re


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

def host_ip_input(accept_empty = False) -> str: 
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
                elif accept_empty == True:
                    valid = True
            except ipaddress.AddressValueError:
                f_print(formater_text('Invalid ipv4 address value', FontTypes.ERROR))
            except Exception as e:
                f_print(formater_text(str(e), FontTypes.ERROR))
        return host_ip

def host_port_input(host_ip) -> int: 
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

def get_user_input():
    print(
        """
        Time to select one or more host(s)
        Provide the subnet using CIDR notation at the end of the IPv4 address if you want to analyze the entire network

        Class legend
        Class A subnet 255.0.0.0 = /8
        Class B subnet 255.255.0.0 = /16
        Class C subnet 255.255.255.0 = /24
        """
    )

    selected_ports = '20-23,42,43,69,80,109,110,115,118,143,144,156,'\
    '161,162,179,220,386,389,443,465,513,514,530,547,587,636,873,989,'\
    '990,993,995,1080,1194,1433,1521,2049,2081,2083,2086,2181,3306,3389,5353,5432,8080'
    
    while True:
        target_ip_address = input_ipv4_re()
        print('\nDo you want to choose the port(s) to be analyzed? If not,'\
             'the analysis will select the most frequent service ports')
        insert_ports = input('Y to yes\n')
        if insert_ports.lower() == 'y':
            if insert_ports.lower() == 'y':
                print(
                    """
                    ### Follow one of the examples ###

                    Single port
                        8080

                    Two or more specific ports
                        443,8080

                    Port range from 0 to 5000
                        0-5000
                    """
                )
                selected_ports = str(host_port_input(target_ip_address))
                return target_ip_address, selected_ports
        else:
            return target_ip_address, selected_ports
