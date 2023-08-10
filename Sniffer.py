import time
from scapy.all import sniff
from user_input import host_ip_input
from sniffer_files.packet_utils import *

# TODO: usar mudolos criados e revisar formatação de texto
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
