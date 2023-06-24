from scapy.all import *
import datetime
import os
import matplotlib.pyplot as plt
from termcolor import colored
from tabulate import tabulate

# Salvo 28-05

while(True):
    try:
        monitorado_ip = input("Informe o endereço IP do aparelho a ser monitorado: ")
        maxPkt = int(input("Informe o número máximo de pacotes para aviso: "))
        intConf = int(input("Informe o tempo de intervalo entre cada análise em segundos: "))
        duracao = int(input("Informe a duração da execução em segundos: "))
        break
    except:
        print(colored("Erro de processamento das entradas", "red"))

periodo = datetime.timedelta(seconds=duracao)

cntRec = 0
cntTurno = 0

turno = []
quantidade = []
listaRepet = []
culpados = []
dadosTabela = []
dadosNovosTabela = []

while True:
    salvar = input("Deseja que a captura seja salva? S para sim ou qualquer outra tecla para não: ")
    if salvar.lower() == "s":
        arquivoNome = input("Informe o nome do arquivo a ser salvo: ")
        arquivoCaminho = input("Informe o caminho completo do local onde o arquivo será salvo ou deixe em branco para salvar no local do script: ")
        if arquivoCaminho != "":
            infSalv = os.path.join(arquivoCaminho, arquivoNome)
        else:
            arquivoCaminho = os.path.dirname(os.path.abspath(__file__))
            infSalv = os.path.join(arquivoCaminho, arquivoNome)

        break
    else:
        arquivoNome = None
        arquivoCaminho = None
        break

# Função para contar o número de pacotes recebidos por um dispositivo
def cadaPacote(packet):
    global cntRec
    if packet.haslayer(IP) and packet[IP].src != monitorado_ip:
        global listaRepet
        listaRepet.append(packet)
    if packet.haslayer(IP) and packet[IP].dst == monitorado_ip:
        cntRec += 1

validaLimite = False

prmMax = True
print(tabulate(dadosTabela, headers=["Leitura", " IP DST", "PACOTES RECEBIDOS", "IP SRC", "MAX PACOTES", "HORA DA LEITURA"], tablefmt="grid"))
inicio = datetime.datetime.now()
fim = inicio + periodo

while datetime.datetime.now() < fim:
    # Inicie a captura de pacotes na rede local para o dispositivo monitorado      
    try:      
        cntTurno += 1
        sniff(prn=cadaPacote, filter="ip", iface="wlxf4ec38924d47", timeout=intConf)
        # Verifique se o número de pacotes recebidos pelo dispositivo excedeu o limite
        hosts = {}
        for pkt in listaRepet:
            if pkt.haslayer(IP):
                ip_src = pkt[IP].src
                if ip_src in hosts:
                    hosts[ip_src] += 1
                else:
                    hosts[ip_src] = 1

        for hosts, count in hosts.items():
            if count > maxPkt:
                culpados.append(hosts)

        if cntRec > maxPkt:
            validaLimite = True
            string_sem_colchetes = ' '.join(str(elemento) for elemento in culpados)
            agora = datetime.datetime.now()
            dadosNovosTabela = [cntTurno, monitorado_ip, cntRec, string_sem_colchetes, maxPkt, agora]
            print(tabulate([[colored(item, 'red') if item == cntRec else item for item in dadosNovosTabela]], tablefmt="grid"))
            culpados.clear()
            if arquivoCaminho and arquivoNome:
                with open(infSalv, "a") as file:
                    if prmMax == True:
                        file.write("Destino;Origem;Numero de pacotes;Segundo(s);Quantidade Maxima;Hora da Leitura\n")
                    file.write(f"{monitorado_ip};{string_sem_colchetes};{cntRec};{intConf};{maxPkt};{agora}\n")
                    prmMax = False
        else:
            culpados.clear()
            agora = datetime.datetime.now()
            dadosNovosTabela = [cntTurno, monitorado_ip, cntRec, "SEM SUSPEITOS", maxPkt, agora]
            print(tabulate([dadosNovosTabela], tablefmt="grid"))          

        quantidade.append(cntRec)
        cntRec = 0
        turno.append(cntTurno)

    except:
        print("Erro de processamento ou parada forçada")

plt.plot(turno, quantidade)

plt.title('Quantidade de leituras por turno')
plt.xlabel('Por segundo(s)')
plt.ylabel('Quantidade de pacotes')

plt.show()
