from pickle import PROTO
from typing import Protocol
from scapy.all import *
from scapy.all import IP, TCP, UDP, ICMP
import time
from termcolor import colored
import os


def cadaPktGeral(packet):
    print('Entrou no print pkt geral')
    print(colored("*******RESUMO DO PACOTE*******", 'white', attrs=['bold']))
    print(packet.summary())
    print()
    print(colored("*******DETALHES DO PACOTE*******", 'white', attrs=['bold']))
    print(packet.show())
    print(colored("*******FIM DO PACOTE*******\n\n", 'white', attrs=['bold']))        

def cada_pkt_geral_salva(packet):
    global pcap_arquivo
    cadaPktGeral(packet)
    wrpcap(os.path.dirname(os.path.abspath(__file__)) + "/" + pcap_arquivo, packet, append=True)

def choose_saving_options():
    salvar = input("Deseja que a leitura seja salva? S para sim ou outra tecla para nao\n")
    if salvar.lower() == "s":
        pcap_arquivo = input("informe o nome do arquivo pcap a ser salvo: ")
        # TODO: não aceitar entrada vazia
    else:
        pcap_arquivo = None
    return pcap_arquivo

def choose_protocol():
    protocolo = input("Gostaria de filtrar um protocolo? S para sim ou outra tecla para não: ")
    if protocolo.lower() == "s":
        while True:
            protocolo_opcao = input("Qual protocolo gostaria de filtrar? 1 = ICMP || 2 = TCP || 3 = UDP ")
            if protocolo_opcao in ["1", "2", "3"]:
                if protocolo_opcao == "1":
                    return "icmp"
                elif protocolo_opcao == "2":
                    return "tcp"
                else:
                    return "udp"
            else:
                print("Protocolo inválido. Por favor, Informe 1, 2 ou 3.")
    return ""

def get_packet_count():
    while True:
        try:
            contador = int(input("Informe o numero de pacotes que deseja analisar: "))
            if contador > 0:
                return contador
            else:
                print("Informe um número positivo maior que zero.")
        except ValueError:
            print("Informe um valor inteiro válido.")

if __name__ == "__main__":
    placaDeRede = 'Wi-Fi'
    alvo = input("Informe um endereço IPV4 local para estar sendo analisado, ou deixe em branco para analisar a rede toda: ")

    pcap_arquivo = choose_saving_options()
    protocolo = choose_protocol()
    contador = get_packet_count()

    t1 = time.time()
    filtro = protocolo
    if alvo: filtro += f'{"" if not protocolo else " and "}host {alvo}'

    
    print("Leitura iniciada...")
    print(alvo, pcap_arquivo)
    if pcap_arquivo:
        print(1)
        sniff(iface=placaDeRede, prn=cada_pkt_geral_salva, count=contador, store=0, 
              filter=filtro)
    else:
        print(2)
        sniff(iface=placaDeRede, prn=cadaPktGeral, count=contador, store=0, filter=filtro)

    t2 = time.time()
    total = t2 - t1 
    print(f"Tempo para leitura: {total}")
