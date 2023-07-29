from printer import FontTypes, formater_text, f_print
from packet_injection_files.packet_types import TCPPacket, UDPPacket, ICMPPacket
from packet_injection_files.send_modes import exponential_send, single_send, overload_send
from typing import Union
from user_input import Protocol, SendMode, choose_protocol, choose_send_mode


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


if __name__ == '__main__':
    try:
        packet = build_packet()

        print(packet.show())
        print(packet.summary())

        send(packet)
    except KeyboardInterrupt:
        print('')
        f_print(formater_text('\nManual interruption', FontTypes.ERROR))