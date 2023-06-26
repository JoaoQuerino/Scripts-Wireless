#TODO: Adicionar docstring

from time import sleep
from scapy.all import sendp
from math import floor


def pos_int_input(message):
    #TODO: Adicionar docstring

    int_input = 0

    while int_input < 1:
        try:
            int_input = int(input(message))

            while int_input < 1:
                print('O entrada deve ser um número inteiro positivo.')
                int_input = int(input(message))
        except ValueError:
            print('O entrada deve ser um número inteiro.')

    return int_input

def pos_float_input(message):
    #TODO: Adicionar docstring

    float_input = -1

    while float_input <= 0:
        try:
            float_input = float(input(message))

            while float_input <= 0:
                print('O entrada deve ser um número real positivo.')
                float_input = float(input(message))
        except ValueError:
            print('O entrada deve ser um número real.')

    return float_input

def exponential_send(packet):
    #TODO: Adicionar docstring

    st_packet_count = pos_int_input('Número inicial de pacotes por envio: ')
    ratio = pos_float_input('Razão de incremento no número de pacotes: ')
    delay = pos_float_input('Atraso entre os envios (em segundos): ')

    packet_count = st_packet_count
    while packet_count >= 1:
        single_send(packet, floor(packet_count))
        sleep(delay)
        packet_count *= ratio

def single_send(packet):
    #TODO: Adicionar docstring

    number_of_packets = pos_int_input('Número de pacotes: ')
    sendp(packet, inter=0, count=number_of_packets)

def overload_send(packet):
    #TODO: Adicionar docstring

    sendp(packet, inter=0, loop=1)