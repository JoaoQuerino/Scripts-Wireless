import time
import os
from scapy.all import IP, TCP, UDP, ICMP, sniff, wrpcap
from printer import FontTypes, formater_text, f_input, f_print
from user_input import host_ip_input


# TODO: usar mudolos criados e revisar formatação de texto
def packet_handler(packet):
    """
    Process and display summary and details of a captured packet.

    Args:
        packet: The captured packet to be processed and displayed.

    Notes:
        This function processes and displays a captured packet's summary and details. It uses
        the Scapy library's built-in methods to show both the summary and the full structure
        of the packet.
    """

    f_print(formater_text("*******PACKAGE SUMMARY*******", 
                          FontTypes.BOLD))
    print(packet.summary())
    print()
    f_print(formater_text("*******PACKAGE DETAILS*******", 
                          FontTypes.BOLD))
    print(packet.show())
    f_print(formater_text("*******PACKAGE END*******\n\n", 
                          FontTypes.BOLD))        

def packet_handler_save(packet):
    """
    Process and save a captured packet.

    Args:
        packet: The captured packet to be processed and saved.

    Notes:
        This function processes and saves captured packets. It appends the provided packet to the
        pcap file specified by 'pcap_file_name'. The packet is first processed by the existing
        packet_handler function.
    """

    global pcap_file_name
    packet_handler(packet)
    wrpcap(os.path.dirname(os.path.abspath(__file__)) + '/' 
           + pcap_file_name, packet, append=True)

def choose_saving_options() -> str:
    """
    Choose whether to save the captured packets to a pcap file.

    Returns:
        str or None: The filename for the pcap file if saving is requested, or None if not saving.

    Notes:
        This function handles user input and validation for choosing whether to save the captured
        packets to a pcap file. It ensures that the user's input is valid and provides the entered
        filename for further use.
    """

    save = f_input(formater_text('Do you want the reading to be saved? (Y/N)', FontTypes.NORMAL))
    if save.lower() == 's':
        pcap_file_name = input('Enter the name of the pcap file to be saved: ')
        # TODO: não aceitar entrada vazia
    else:
        pcap_file_name = None
    return pcap_file_name

def choose_protocol() -> str:
    """
    Choose a protocol to filter packets by.

    Returns:
        str: The chosen protocol to filter packets by, or an empty string if no filtering.

    Raises:
        ValueError: If the user input is not 'Y' or 'N'.

    Notes:
        This function handles user input and validation for selecting a protocol for packet filtering.
        It ensures that the user's input is valid and corresponds to the available options.
    """

    protocol = input('Would you like to filter a protocol? (Y/N) ')
    if protocol.lower() == "s":
        while True:
            protocol_type = input("Which protocol would you like to filter? 1 = ICMP || 2 = TCP || 3 = UDP ")
            if protocol_type in ['1', '2', '3']:
                if protocol_type == '1':
                    return 'icmp'
                elif protocol_type == '2':
                    return 'tcp'
                else:
                    return 'udp'
            else:
                f_print(formater_text('Invalid protocol. Please enter 1, 2 or 3.', FontTypes.ALERT))
    elif protocol.lower() == 'n':
        return ''
    else:
        raise ValueError('Input is not Y or N')

def get_packet_count() -> str:
    """
    Get the number of packets to be captured and analyzed.

    Returns:
        int: The number of packets to capture and analyze.

    Notes:
        This function handles user input to ensure a valid positive integer value is provided.
        It repeatedly prompts the user until a valid input is given.
    """

    while True:
        try:
            counter = int(input('Enter the number of packages you want to analyze: '))
            if counter > 0:
                return counter
            else:
                print('Enter a positive number greater than zero.')
        except ValueError:
            f_print(formater_text('Please enter a valid integer value.', FontTypes.ALERT))

if __name__ == '__main__':
    """
    This script captures and analyzes network packets using a packet sniffer.
    
    Usage:
        Run this script to capture and analyze network packets using the specified
        configuration options.
    
    Configuration:
        - interface: The network interface to capture packets from (e.g., 'Wi-Fi').
        - monitored_device: The IPV4 address to analyze or None to analyze the entire network.
        - pcap_file_name: The name of the pcap file to save packets or None to not save.
        - protocol: The protocol to filter packets by (e.g., 'tcp', 'udp', 'icmp').
        - counter: The number of packets to capture and analyze.    
    """

    interface = 'Wi-Fi'
    print('Enter a local IPV4 address to be analyzed, or leave it blank to analyze the entire local network')
    monitored_device = host_ip_input(accept_empty = True)

    pcap_file_name = choose_saving_options()
    protocol = choose_protocol()
    counter = get_packet_count()

    t1 = time.time()
    reading_filter = protocol
    if monitored_device: reading_filter += f'{"" if not protocol else " and "}host {monitored_device}'

    
    print('Reading started...')
    print(monitored_device, pcap_file_name)
    if pcap_file_name:
        print(1)
        sniff(iface=interface, prn=packet_handler_save, count=counter, store=0, 
              filter=reading_filter)
    else:
        print(2)
        sniff(iface=interface, prn=packet_handler, count=counter, store=0, filter=reading_filter)

    t2 = time.time()
    total = t2 - t1 
    print(f"Time for reading: {total}")
