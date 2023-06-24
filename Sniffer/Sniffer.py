from scapy.all import *
import time
import sys
from termcolor import colored
import os

def cadaPktGeral(packet):
    print(colored("*******RESUMO DO PACOTE*******", 'white', attrs=['bold']))
    print(packet.summary())
    print()
    print(colored("*******DETALHES DO PACOTE*******", 'white', attrs=['bold']))
    print(packet.show())
    print(colored("*******FIM DO PACOTE*******\n\n", 'white', attrs=['bold']))
    if pcap_arquivo and pcap_caminho:
        wrpcap(pcap_caminho + "/" + pcap_arquivo, packet, append=True)

def cadaPkt(packet):
    global contador
    if packet.haslayer(IP) and (packet[IP].src == alvo or packet[IP].dst == alvo):
        print(colored("*******RESUMO DO PACOTE*******", 'white', attrs=['bold']))
        print(packet.summary())
        print()
        print(colored("*******DETALHES DO PACOTE*******", 'white', attrs=['bold']))
        print(packet.show())
        print(colored("*******FIM DO PACOTE*******\n\n", 'white', attrs=['bold']))
        if pcap_arquivo and pcap_caminho:
            wrpcap(pcap_caminho + "/" + pcap_arquivo, packet, append=True)
    else:
        contador -=1
    # Se o nome do arquivo de captura e o caminho estiverem definidos, salve o pacote no arquivo

try:
    placaDeRede = 'wlxf4ec38924d47' 
    alvo = input("Informe um endereço IPV4 local para estar sendo analisado, ou deixe em branco para analisar a rede toda: ")
    salvar = None

    while(1):
        salvar = input("Deseja que a leitura seja salva? S para sim ou outra tecla para nao\n")
        if salvar.lower() == "s":
            pcap_arquivo = input("Informe o nome do arquivo pcap a ser salvo: ")
            pcap_caminho = input("Informe o caminho de salvamento do arquivo PCAP ou deixe em branco para salvar no local do script: ")
            if pcap_caminho == "":
                #Pega caminho do script
                pcap_caminho = os.path.dirname(os.path.abspath(__file__))

            break
        else:
            pcap_arquivo = None
            pcap_caminho = None
            break

    while True:
        protocolo = input("Gostaria de filtrar um protocolo? S para sim ou outra tecla para não: ")
        if protocolo.lower() == "s":
            while True:
                protocolo_opcao = input("Qual protocolo gostaria de filtrar? 1 = ICMP || 2 = TCP || 3 = UDP ")
                if protocolo_opcao == "1":
                    protocolo = "icmp"
                    break
                elif protocolo_opcao == "2":
                    protocolo = "tcp"
                    break
                elif protocolo_opcao == "3":
                    protocolo = "udp"
                    break
                else:
                    print("Protocolo inválido. Por favor, Informe 1, 2 ou 3.")
            break
        else:
            protocolo = ""
            break

    while(1):
        try:
            contador = int(input("Informe o numero de pacotes que deseja analisar: "))
            if contador >= 1:
                break

        except ValueError:
            print("Entrada inválida. Por favor, informe um número inteiro válido.")
            

    if __name__ == "__main__":
        t1 = time.time()
        filtro = ""
        if protocolo:
            filtro += protocolo
        print("Leitura iniciada...")
        if alvo != "":
            sniff(iface=placaDeRede, prn=cadaPkt, count=contador, store=0, filter=filtro)
        else:
            sniff(iface=placaDeRede, prn=cadaPktGeral, count=contador, store=0, filter=filtro)
        t2 = time.time()
        total = t2 - t1 
        print(f"Tempo para leitura: {total}")

except:
    print(errno)
    print(colored("\nErro de leitura ou finalizado manualmente", "red"))