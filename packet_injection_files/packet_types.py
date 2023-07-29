from abc import ABC
from scapy.all import IP, TCP, UDP, ICMP, RandMAC, Ether, RandIP, get_if_hwaddr, Packet, get_if_list
from printer import FontTypes, formater_text, f_print, f_input
from user_input import host_ip_input, host_port_input, payload_input


class AbstractPacket(ABC):
    """
    Abstract base class for packet building.

    Provides common methods for building packets.
    """

    def packet_builder(self) -> Packet:
        """
        Builds the packet based on user inputs and returns it.

        :return: The built packet.
        """

        host_ip = self.host_ip_input()
        host_port = self.host_port_input(host_ip)
        chosen_layer = self.get_layer(host_port)
        payload = self.payload_input()
                             
        use_rand_mac_and_ip = f_input(f'{formater_text("Want to use random MAC and IP address?", FontTypes.NORMAL)} '\
            f'({formater_text("Y for yes", FontTypes.BOLD)}): ').upper() == 'Y'
        
        if not use_rand_mac_and_ip:
            available_interfaces = get_if_list()
            available_interfaces_str = ', '.join(
                [formater_text(i, FontTypes.BOLD) for i in available_interfaces]
                )
            interface = f_input(f'{formater_text("Select a available interface", FontTypes.NORMAL)} ({available_interfaces_str}): ')

            while interface not in available_interfaces:
                if interface != '':
                    f_print(formater_text(f'{interface} is not an available interface.', FontTypes.ERROR))

                interface = f_input(f'{formater_text("Select a available interface", FontTypes.NORMAL)} ({available_interfaces_str}): ')

            try:
                ether_layer = Ether(src=get_if_hwaddr(interface))
            except Exception as e:
                f_print(formater_text(str(e), FontTypes.ERROR))

            ip_layer = IP(dst=host_ip)
        else:        
            ether_layer = Ether(src=RandMAC())
            ip_layer = IP(dst=host_ip, src=RandIP())

        packet = ether_layer / ip_layer / chosen_layer / payload

        return packet

    def host_ip_input(self) -> str: 
        """
        Prompts the user to enter the IP address of the destination host.

        :return: The entered host IP address.
        """

        return host_ip_input()
    
    def host_port_input(self, host_ip) -> str: 
        """
        Prompts the user to enter the destination port.

        :param host_ip: The IP address of the destination host.
        :return: The entered destination port.
        """

        return host_port_input(host_ip)

    def payload_input(self) -> str:
        """
        Prompts the user to enter a payload for the packet.

        :return: The entered payload.
        """

        return payload_input()

    def get_layer(self, host_port):
        """
        Retrieves the appropriate layer for the packet based on the host port.

        :param host_port: The destination port.
        :return: The layer object for the packet.
        """

        raise NotImplementedError


class TCPPacket(AbstractPacket):
    """
    Class representing a TCP packet.

    Inherits from AbstractPacket.
    """
    
    def get_layer(self, host_port) -> TCP:
        """
        Retrieves the TCP layer for the packet based on the host port.

        :param host_port: The destination port.
        :return: The TCP layer object for the packet.
        """

        return TCP(dport=host_port)


class UDPPacket(AbstractPacket):
    """
    Class representing a UDP packet.

    Inherits from AbstractPacket.
    """

    def get_layer(self, host_port) -> UDP: 
        """
        Retrieves the UDP layer for the packet based on the host port.

        :param host_port: The destination port.
        :return: The UDP layer object for the packet.
        """

        return UDP(dport=host_port)


class ICMPPacket(AbstractPacket):
    """
    Class representing an ICMP packet.

    Inherits from AbstractPacket.
    """

    def host_port_input(self, host_ip) -> str:
        """
        Overrides the host_port_input method to return an empty string.

        :param host_ip: The IP address of the destination host.
        :return: An empty string.
        """

        return ''

    def get_layer(self, host_port) -> ICMP: #TODO: verificar possiveis excess�es
        """
        Retrieves the ICMP layer for the packet.

        :param host_port: The destination port.
        :return: The ICMP layer object for the packet.
        """

        return ICMP()