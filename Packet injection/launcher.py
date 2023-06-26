#TODO: Adicionar docstring

from enum import Enum
from packet_types import TCPPacket, UDPPacket, ICMPPacket
from send_modes import exponential_send, single_send, overload_send


class Protocol(Enum):
    #TODO: Adicionar docstring

    TCP = 0
    UDP = 1
    ICMP = 2


class SendMode(Enum):
    #TODO: Adicionar docstring

    EXPONENTIAL = 0
    SINGLE = 1
    OVERLOAD = 2


def choose_protocol():
    """
    Prompts for input of a supported protocol until one is entered.
    Returns the supported protocol entered as a Protocol Enum.
    """

    supported_protocols = [p.name for p in Protocol]
    supported_protocols_str = ', '.join(supported_protocols)
    protocol = input(f'Select a supported packet type ({supported_protocols_str}): ').upper()

    while protocol not in supported_protocols:
        print(f'{protocol} is not a supported protocol.')
        protocol = input(f'Select a supported packet type ({supported_protocols_str}): ').upper()

    return Protocol(supported_protocols.index(protocol))

def build_packet():
    #TODO: Adicionar docstring

    protocol = choose_protocol()

    if protocol == Protocol.TCP:
        return TCPPacket().packet_builder()

    if protocol == Protocol.UDP:
        return UDPPacket().packet_builder()

    if protocol == Protocol.ICMP:
        return ICMPPacket().packet_builder()

    raise NotImplementedError

def choose_send_mode():
    """
    Prompts for input of a supported send mode until one is entered.
    Returns the supported send mode entered as a SendMode Enum.
    """

    supported_send_modes = [sm.name for sm in SendMode]
    supported_send_modes_str = ', '.join(supported_send_modes)
    send_mode = input(f'Select a supported send mode ({supported_send_modes_str}): ').upper()

    while send_mode not in supported_send_modes:
        print(f'{send_mode} is not a supported send mode.')
        send_mode = input(f'Select a supported send mode ({supported_send_modes_str}): ').upper()

    return SendMode(supported_send_modes.index(send_mode))

def send(packet):
    #TODO: Adicionar docstring

    send_mode = choose_send_mode()

    if send_mode == SendMode.EXPONENTIAL:
        exponential_send(packet)

    elif send_mode == SendMode.SINGLE:
        single_send(packet)

    elif send_mode == SendMode.OVERLOAD:
        overload_send(packet)

    else:
        raise NotImplementedError

if __name__ == '__main__':
    packet = build_packet()

    print(packet.show())
    print(packet.summary())

    send(packet)