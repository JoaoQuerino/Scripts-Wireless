from enum import Enum
from packet_types import TCPPacket, UDPPacket, ICMPPacket
from send_modes import exponential_send, single_send, overload_send
from termcolor import cprint
from Views.Printer import FontTypes, formater_text
from typing import Union


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


def choose_protocol() -> Protocol:
    """
    Prompts for input of a supported protocol until one is entered.
    Returns the supported protocol entered as a Protocol Enum.
    """

    supported_protocols = [p.name for p in Protocol]
    supported_protocols_str = ', '.join(supported_protocols)
    protocol = input(f'Select a supported packet type ({supported_protocols_str}): ').upper()

    while protocol not in supported_protocols:
        print(formater_text('{} is not a supported protocol.'.format(Protocol), ))
        protocol = input(f'Select a supported packet type ({supported_protocols_str}): ').upper()

    return Protocol(supported_protocols.index(protocol))
    
def build_packet() -> Union[TCPPacket, UDPPacket, ICMPPacket]:
    """
    Builds a packet based on the selected protocol.
    Returns the built packet.
    """

    protocol = choose_protocol()

    if protocol == Protocol.TCP:
        return TCPPacket().packet_builder()

    if protocol == Protocol.UDP:
        return UDPPacket().packet_builder()

    if protocol == Protocol.ICMP:
        return ICMPPacket().packet_builder()

    raise NotImplementedError

def choose_send_mode() -> SendMode:
    """
    Prompts for input of a supported send mode until one is entered.
    Returns the supported send mode entered as a SendMode Enum.
    """

    supported_send_modes = [sm.name for sm in SendMode]
    supported_send_modes_str = ', '.join(supported_send_modes)
    send_mode = input(f'Select a supported send mode ({supported_send_modes_str}): ').upper()

    while send_mode not in supported_send_modes:
        print(formater_text('{} is not a supported send mode.'.format(send_mode), FontTypes.ERROR, [0, 1, 2, 3, 4, 5, 6])) 
        send_mode = input(f'Select a supported send mode ({supported_send_modes_str}): ').upper()

    return SendMode(supported_send_modes.index(send_mode))

def send(packet):
    """
    Sends a packet based on the selected send mode.

    :param packet: The packet to be sent.
    """

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
    try:
        packet = build_packet()

        print(packet.show())
        print(packet.summary())

        send(packet)
    except KeyboardInterrupt:
        print(formater_text('\nManual interruption', FontTypes.ERROR, [0,1]))