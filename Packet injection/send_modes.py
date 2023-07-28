from time import sleep
from scapy.all import sendp
from math import floor
from termcolor import cprint
from Views.Printer import FontTypes, formater_text


def pos_int_input(message) -> int:
    """
    Function to prompt the user for a positive integer input.

    :param message: The prompt message to display to the user.
    :return: The positive integer input provided by the user.
    """
    int_input = 0

    while int_input < 1:
        try:
            int_input = int(input(message))

            while int_input < 1:
                print(formater_text('The input must be a positive integer.', FontTypes.ERROR, [0, 1, 2, 3, 4, 5, 6]))
                int_input = int(input(message))
        except ValueError:
            print(formater_text('The input must be an integer.', FontTypes.ERROR, [0, 1, 2, 3, 4, 5]))

    return int_input

def pos_float_input(message) -> float:
    """
    Function to prompt the user for a positive floating-point input.

    :param message: The prompt message to display to the user.
    :return: The positive floating-point input provided by the user.
    """
    float_input = -1

    while float_input <= 0:
        try:
            float_input = float(input(message))

            while float_input <= 0:
                print(formater_text('The input must be a positive real number.', FontTypes.ERROR, [0, 1, 2, 3, 4, 5, 6, 7]))
                float_input = float(input(message))
        except ValueError:
            print(formater_text('The input must be a real number.', FontTypes.ERROR, [0, 1, 2, 3, 4, 5, 6]))

    return float_input

def exponential_send(packet):
    """
    Function to send packets with exponential growth.

    :param packet: The packet to be sent.
    """
    packet_count = pos_int_input('Initial number of packets per send: ')
    ratio = pos_float_input('Ratio of packet count increment: ')
    delay = pos_float_input('Delay between sends (in seconds): ')

    try:
        while packet_count >= 1:
            sendp(packet, inter=0, count=floor(packet_count))
            sleep(delay)
            packet_count *= ratio
    except KeyboardInterrupt:
        print(formater_text('Manual interruption', FontTypes.ERROR, [0, 1]))

def single_send(packet):
    """
    Function to send a single batch of packets.

    :param packet: The packet to be sent.
    """
    number_of_packets = pos_int_input('Number of packets: ')
    try:
        sendp(packet, inter=0, count=number_of_packets)
    except KeyboardInterrupt:
        print(formater_text('Manual interruption', FontTypes.ERROR, [0, 1]))

def overload_send(packet):
    """
    Function to send packets in a traffic overload.

    :param packet: The packet to be sent.
    """
    sendp(packet, inter=0, loop=1)

def arithmetic_send(packet):
    """
    Function to send packet in a PA.

    :param packet: The packet to send.
    """
    packet_count = pos_int_input('Initial number of packets per send: ')
    increment = pos_int_input('Packet count increment: ')
    delay = pos_float_input('Delay between sends (in seconds): ')

    try:
        while packet_count >= 1:
            sendp(packet, inter=0, count=floor(packet_count))
            sleep(delay)
            packet_count += increment
    except KeyboardInterrupt:
        print(formater_text('Manual interruption', FontTypes.ERROR, [0, 1]))
