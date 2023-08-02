import re
import socket
import time
import nmap
from printer import FontTypes, formater_text, f_input, f_print
from common import get_all_ips
from user_input import host_ip_input, host_port_input, get_user_input


f_print(formater_text('Welcome\n', FontTypes.BOLD))

list_IP = get_all_ips()
f_print('Your IPv4 are:' + formater_text(list_IP, FontTypes.BOLD))


def start_scan(target_ip_address:str, selected_ports:str):
    print(2)
    f_print(formater_text('Scan started, please wait...', FontTypes.BOLD))
    start_read_time = time.time()
    scanner = nmap.PortScanner()
    print(1)
    # Parâmetros para detecção de SO, usando escaneamento do tipo SYN exi
    result = scanner.scan(target_ip_address, selected_ports, '-A -sS --osscan-guess --min-rate=50000 -T3')

    #Parte que exibe no terminal
    print("--------------------------------------------------")
    f_print(formater_text('***HOST LIST***', FontTypes.BOLD))
    print('Number of devices: ', len(result['scan']))
    print()
    for cont, device_ip in enumerate(result['scan'], start=1):
        f_print(formater_text(f'ID: {cont}', FontTypes.BOLD, [1]))
        f_print(formater_text(f'IP: {device_ip}', FontTypes.BOLD, [1]))
        tcp_info = result['scan'][device_ip].get('tcp', {})
        if tcp_info:
            print('Result of search using TCP send')
            for port, port_info in tcp_info.items():
                f_print(formater_text(f'Port found: {port} / Reason - {port_info.get("reason", "unknown")}', FontTypes.BOLD))
                service = port_info.get('name')
                if service:
                    f_print(formater_text(f'   Service: running in port {port}: {service}', FontTypes.BOLD))
                else:
                    f_print('   Service: ' + formater_text('unknown', FontTypes.ALERT))

        else:
            f_print(formater_text('Ports found: 0', FontTypes.BOLD))

        mac = result['scan'][device_ip].get('addresses', {}).get('mac', formater_text('unknow', FontTypes.ALERT))
        f_print(formater_text(f'MAC: {mac}', FontTypes.BOLD))
        vendor = result['scan'][device_ip].get('vendor', {})
        if vendor:
            for fabricator in vendor:
                f_print(formater_text(f'Fabricator: {vendor[fabricator]}', FontTypes.BOLD))
        else:
            f_print(formater_text('Fabricante: ', FontTypes.NORMAL) + formater_text('Falha ao obter', FontTypes.ALERT))

        reacao = result['scan'][device_ip].get('status', {}).get('reason', formater_text('Falha ao obter', FontTypes.ALERT))
        f_print(formater_text(f'Meio de resposta: {reacao}', FontTypes.BOLD))
        sistema_operacional = result['scan'][device_ip].get('osmatch', [])
        if sistema_operacional:
            print(formater_text(f"Sistema operacional: {sistema_operacional[0]['name']}", FontTypes.BOLD))
        else:
            f_print(formater_text('Sistema operacional: ', FontTypes.BOLD), formater_text('Falha ao obter', FontTypes.BOLD))

        print("")
    end_read_time = time.time()
    print(f"Tempo de processamento: {end_read_time - start_read_time}")

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
        start_time = time.time()
        try:
            user_inputs = get_user_input()
            alvoG, portasSelecionadasG = user_inputs
            start_scan(alvoG, portasSelecionadasG)
        except BaseException as e:
            print(e)
            f_print(formater_text('\nFinalizaçao manual executada', 
                                  FontTypes.ERROR))

        elapsed_time = time.time() - start_time
        if elapsed_time < 2:
            f_print(formater_text('\n### Houve um erro no processamento'\
               'das entradas, revise-as e tente novamente ###\n', FontTypes.ERROR))
        else:
            break
        