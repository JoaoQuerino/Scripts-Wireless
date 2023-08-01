import re
import socket
import time
import nmap
from printer import FontTypes, formater_text
from common import get_all_ips
from user_input import host_ip_input, host_port_input


print(formater_text('Welcome\n', FontTypes.BOLD))

list_IP = get_all_ips()
print('Your IPv4 are:', formater_text(list_IP, FontTypes.BOLD))

def get_user_input():
    print(
        """
        Time to select one or more host(s)
        Provide the subnet using CIDR notation at the end of the IPv4 address if you want to analyze the entire network

        Class legend
        Class A subnet 255.0.0.0 = /8
        Class B subnet 255.255.0.0 = /16
        Class C subnet 255.255.255.0 = /24
        """
    )

    selected_ports = '20-23,42,43,69,80,109,110,115,118,143,144,156,'\
    '161,162,179,220,386,389,443,465,513,514,530,547,587,636,873,989,'\
    '990,993,995,1080,1194,1433,1521,2049,2081,2083,2086,2181,3306,3389,5353,5432,8080'
    
    while True:
        target_ip_address = host_ip_input()
        print('\nDo you want to choose the port(s) to be analyzed? If not,'\
             'the analysis will select the most frequent service ports')
        insert_ports = input('Y to yes\n')
        if insert_ports.lower() == 'y':
            if insert_ports.lower() == 'y':
                print(
                    """
                    ### Follow one of the examples ###

                    Single port
                        8080

                    Two or more specific ports
                        443,8080

                    Port range from 0 to 5000
                        0-5000
                    """
                )
                selected_ports = host_port_input(target_ip_address)
                return target_ip_address, selected_ports
        else:
            return target_ip_address, selected_ports

def start_scan(target_ip_address:str, selected_ports:str):
    print('Scan started, please wait...')
    start_read_time = time.time()
    scanner = nmap3.PortScanner()

    # Parâmetros para detecção de SO, usando escaneamento do tipo SYN exi
    result = scanner.scan(target_ip_address, selected_ports, '-A -sS --osscan-guess --min-rate=50000 -T3')

    #Parte que exibe no terminal
    print("--------------------------------------------------")
    print(formater_text('***HOST LIST***', FontTypes.BOLD))
    print('Number of devices: ', len(result['scan']))
    print()
    for cont, device_ip in enumerate(result['scan'], start=1):
        print(formater_text(f'ID: {cont}', FontTypes.BOLD, [1]))
        print(formater_text(f'IP: {device_ip}', FontTypes.BOLD, [1]))
        tcp_info = result['scan'][device_ip].get('tcp', {})
        if tcp_info:
            print('Result of search using TCP send')
            for port, port_info in tcp_info.items():
                print(formater_text(f'Port found: {port} / Reason - {port_info.get("reason", "unknown")}', FontTypes.BOLD))
                service = port_info.get('name')
                if service:
                    print(formater_text(f'   Service: running in port {port}: {service}', FontTypes.BOLD))
                else:
                    print('   Service: ' + formater_text('unknown', FontTypes.ALERT))

        else:
            print(colored('Ports found: 0',attrs=['bold']))

        mac = result['scan'][device_ip].get('addresses', {}).get('mac', formater_text('unknow', FontTypes.ALERT))
        print(formater_text(f'MAC: {mac}', FontTypes.BOLD))
        vendor = result['scan'][device_ip].get('vendor', {})
        if vendor:
            for fabricator in vendor:
                print(formater_text(f'Fabricator: {vendor[fabricator]}', FontTypes.BOLD))
        else:
            print(colored("Fabricante: ", attrs=['bold']), colored('Falha ao obter','yellow', attrs=['bold']))

        reacao = result['scan'][device_ip].get('status', {}).get('reason', colored('Falha ao obter', 'yellow', attrs=['bold']))
        print(colored(f"Meio de resposta: {reacao}", attrs=['bold']))
        sistema_operacional = result['scan'][device_ip].get('osmatch', [])
        if sistema_operacional:
            print(colored(f"Sistema operacional: {sistema_operacional[0]['name']}", attrs=['bold']))
        else:
            print(colored("Sistema operacional:", attrs=['bold']), colored("Falha ao obter", 'yellow', attrs=['bold']))

        print("")
    final_Scan = time.time()
    print(f"Tempo de processamento: {final_Scan - inicio_Scan}")

    #Salva em arquivo
    nomeArq = input('\nInforme o nome do arquivo para salvamento da leitura:\n')
    output_file = open(f"{nomeArq}.txt", "w")
    output_file.write("--------------------------------------------------\n")
    output_file.write("*** HOST(S) CONECTADOS ***\n")
    output_file.write("Numero total: " + str(len(result['scan'])) + "\n\n")

    for cont, device_ip in enumerate(result['scan'], start=1):
        output_file.write("ID: " + str(cont) + "\n")
        output_file.write("IP: " + device_ip + "\n")
        tcp_info = result['scan'][device_ip].get('tcp', {})
        if tcp_info:
            output_file.write("Resultado de consulta usando protocolo TCP\n")
            for porta, port_info in tcp_info.items():
                output_file.write("Porta reconhecida: " + str(porta) + " / Reação - " + str(port_info.get('reason', 'Desconhecido')) + "\n")
                servico = port_info.get('name')
                if servico:
                    output_file.write("   Serviço rodando na porta " + str(porta) + ": " + servico + "\n")
                else:
                    output_file.write("   Serviço: Falha ao obter\n")

        else:
            output_file.write("Portas reconhecidas: 0\n")

        mac = result['scan'][device_ip].get('addresses', {}).get('mac', 'Falha ao obter')
        output_file.write("MAC: " + str(mac) + "\n")
        vendor = result['scan'][device_ip].get('vendor', {})
        if vendor:
            for fab in vendor:
                output_file.write("Fabricante: " + vendor[fab] + "\n")
        else:
            output_file.write("Fabricante: Falha ao obter\n")

        reacao = result['scan'][device_ip].get('status', {}).get('reason', 'Falha ao obter')
        output_file.write("Meio de resposta: " + str(reacao) + "\n")
        sistema_operacional = result['scan'][device_ip].get('osmatch', [])
        if sistema_operacional:
            output_file.write("Sistema operacional: " + str(sistema_operacional[0]['name']) + "\n")
        else:
            output_file.write("Sistema operacional: Falha ao obter\n")

        output_file.write("\n")

    output_file.close()
    print(f"Resultado da análise salvo como '{nomeArq}.txt', ele esta salvo na pasta localizada o script")

if __name__ == '__main__':
    while True:
        try:
            retorn = get_user_input()
            alvoG, portasSelecionadasG = retorn
            start_time = time.time()
            start_scan(alvoG, portasSelecionadasG)
        except:
            print(colored("\nFinalizaçao manual executada", "red"))

        elapsed_time = time.time() - start_time
        if elapsed_time and elapsed_time < 2:
            print(colored('\n### Houve um erro no processamento das entradas, revise-as e tente novamente ###\n', 'red'))
        else:
            break
