import datetime
from tabulate import tabulate
from scapy.all import IP, sniff
from user_input import host_ip_input, get_user_input_generic, get_save_option, get_interface
from printer import FontTypes, formater_text, f_print
from anomaly_monitor_files.anomaly_monitor_utils import plot_reading_data


file_path = None
file_name = None
received_counter = 0 # CONTADOR DE PACOTES DA MESMA ORIGEM
read_counter = 0 # CONTADOR DE LEITURAS ANALISADAS
received_total = 0
reading = []
quantity_of_packages = []
send_counter_by_source = []
source_list = []
table_data = []
new_table_data = []
reading_media = []
first_maximum = True
# TODO: usar modulos próprios, aplicar boas praticas como saida esperada, 
# identação e nomes de funções/variaveis, ajustar impressao dos suspeitos

monitored_ip = host_ip_input()

maximum_to_alert = get_user_input_generic(
    "Enter the maximum number of packages for notice: ",
    'Input maximum number processing error'
)
interval_in_seconds = get_user_input_generic(
    "Enter the interval time between each analysis in seconds: ",
    'Input interval processing error'
)
duration = get_user_input_generic(
    "Enter duration of execution in seconds: ",
    'Input duration processing error'
)
interface = get_interface()
period = datetime.timedelta(seconds=duration)

# TODO: revisar funçao de salvamento, para ficar 
# passando none para o caso o usuário nao queira salvar
infSalv = get_save_option()

def packet_handler(packet):
    global received_counter
    if packet.haslayer(IP) and packet[IP].src != monitored_ip:
        global send_counter_by_source
        send_counter_by_source.append(packet)
    if packet.haslayer(IP) and packet[IP].dst == monitored_ip:
        received_counter += 1

print(tabulate(table_data, headers=["READING", " IP DST", 
                                    "RECEIVED PACKET", "IP SRC", 
                                    "MAX PACKET", "READING TIME"], tablefmt="grid"))
start_monitoring = datetime.datetime.now()
stop_monitoring = start_monitoring + period

if __name__ == "__main__":
    while datetime.datetime.now() < stop_monitoring:  
        try:      
            read_counter += 1
            sniff(prn=packet_handler, filter="ip", iface=interface, 
                  timeout=interval_in_seconds)
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
        
            hosts = {}
            if received_counter >= maximum_to_alert:
                string_without_brackets = ' '.join(str(element) 
                                                   for element in source_list)
                reading_moment = datetime.datetime.now()
                reading_moment = reading_moment.strftime("%Y-%m-%d %H:%M:%S")
                new_table_data = [read_counter, monitored_ip, received_counter, 
                                  string_without_brackets, maximum_to_alert, 
                                  reading_moment]
                f_print(tabulate([[formater_text(item, FontTypes.ERROR) 
                                   if item == received_counter else item 
                                   for item in new_table_data]], tablefmt="grid"))
                source_list.clear()
                if file_path and file_name:
                    with open(infSalv, "a") as file:
                        if first_maximum == True:
                            file.write("Destiny;Source;Number of packages;'\
                            Seconds;Maximum amount;Reading moment\n")
                        file.write(f"{monitored_ip};{string_without_brackets};'\
                            '{received_counter};{interval_in_seconds};{maximum_to_alert};{reading_moment}\n")
                        first_maximum = False
            else:
                source_list.clear()
                read_time = datetime.datetime.now()
                read_time = read_time.strftime("%Y-%m-%d %H:%M:%S")
                new_table_data = [read_counter, monitored_ip, received_counter, 
                                  "No suspect", maximum_to_alert, read_time]
                print(tabulate([new_table_data], tablefmt="grid"))          
        
            received_total += received_counter 
            quantity_of_packages.append(received_counter)
            reading_media.append(received_total / read_counter)
            received_counter = 0
            reading.append(read_counter)
        except KeyboardInterrupt:
            print('forced stop')
        except Exception as e:
            print("Processing error: " + str(e))

plot_reading_data(reading, reading_media, quantity_of_packages)