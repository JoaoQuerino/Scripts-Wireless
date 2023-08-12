from scapy.all import IP, sniff
import datetime
import os
import matplotlib.pyplot as plt
from termcolor import colored
from tabulate import tabulate
from user_input import host_ip_input
from printer import FontTypes, formater_text, f_input, f_print


# TODO: Padronizar lingua, usar modulos próprios, aplicar boas praticas como saida esperada, identação e nomes de funções/variaveis
monitored_ip = host_ip_input()
while(True):
    try:
        
        maximum_to_alert = int(input("Enter the maximum number of packages for notice: "))
        interval_in_seconds = int(input("Enter the interval time between each analysis in seconds: "))
        duration = int(input("Enter duration of execution in seconds: "))
        break
    except:
        f_print(formater_text('Input processing error', FontTypes.ALERT))

period = datetime.timedelta(seconds=duration)

received_counter = 0
read_counter = 0

reading = []
quantity_of_packages = []
send_counter_by_source = []
source_list = []
table_data = []
new_table_data = []

while True:
    save = input("Deseja que a captura seja salva? S para sim ou qualquer outra tecla para não: ")
    if save.lower() == "s":
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
def packet_handler(packet):
    global received_counter
    if packet.haslayer(IP) and packet[IP].src != monitored_ip:
        global send_counter_by_source
        send_counter_by_source.append(packet)
    if packet.haslayer(IP) and packet[IP].dst == monitored_ip:
        received_counter += 1

check_limit = False

first_maximum = True
print(tabulate(table_data, headers=["Leitura", " IP DST", "PACOTES RECEBIDOS", "IP SRC", "MAX PACOTES", "HORA DA LEITURA"], tablefmt="grid"))
start_monitoring = datetime.datetime.now()
stop_monitoring = start_monitoring + period

while datetime.datetime.now() < stop_monitoring:
    # Inicie a captura de pacotes na rede local para o dispositivo monitorado      
    try:      
        read_counter += 1
        sniff(prn=packet_handler, filter="ip", iface="Wi-Fi", timeout=interval_in_seconds)
        # Verifique se o número de pacotes recebidos pelo dispositivo excedeu o limite
        hosts = {}
        for pkt in send_counter_by_source:
            if pkt.haslayer(IP):
                ip_src = pkt[IP].src
                if ip_src in hosts:
                    hosts[ip_src] += 1
                else:
                    hosts[ip_src] = 1

        for hosts, count in hosts.items():
            if count > maximum_to_alert:
                source_list.append(hosts)

        if received_counter > maximum_to_alert:
            check_limit = True
            string_without_brackets = ' '.join(str(element) for element in source_list)
            reading_moment = datetime.datetime.now()
            new_table_data = [read_counter, monitored_ip, received_counter, string_without_brackets, maximum_to_alert, reading_moment]
            print(tabulate([[colored(item, 'red') if item == received_counter else item for item in new_table_data]], tablefmt="grid"))
            source_list.clear()
            if arquivoCaminho and arquivoNome:
                with open(infSalv, "a") as file:
                    if first_maximum == True:
                        file.write("Destino;Origem;Numero de pacotes;Segundo(s);Quantidade Maxima;Hora da Leitura\n")
                    file.write(f"{monitored_ip};{string_without_brackets};{received_counter};{interval_in_seconds};{maximum_to_alert};{reading_moment}\n")
                    first_maximum = False
        else:
            source_list.clear()
            read_time = datetime.datetime.now()
            new_table_data = [read_counter, monitored_ip, received_counter, "SEM SUSPEITOS", maximum_to_alert, read_time]
            print(tabulate([new_table_data], tablefmt="grid"))          

        quantity_of_packages.append(received_counter)
        received_counter = 0
        reading.append(read_counter)
    except KeyboardInterrupt:
        print('forced stop')
    except Exception as e:
        print("Processing error: " + str(e))

plt.plot(reading, quantity_of_packages)

plt.title('Number of readings per shift')
plt.xlabel('per second(s)')
plt.ylabel('quantity of packages')

plt.show()
