import nmap 
import psutil
import socket
import time
import re
from termcolor import colored

print(colored('Bem vindo\n', 'white', attrs=['bold']))

# Pega os endereços IP do computador
def get_all_ips():
    ip_list = []
    for i in psutil.net_if_addrs().values():
        for j in i:
            if j.family == socket.AF_INET:
                ip_list.append(j.address)
    return ip_list

#Valida se a string passada e um IPv4 usando expressao regular
def validaIPv4(IP):
    molde = r'^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$'
    if not bool(re.match(molde, IP)):
        return False

    parts = IP.split('.')
    if len(parts) == 5:
        mask = int(parts[4])
        if not (0 <= mask <= 32):
            return False

    return all(0 <= int(part) < 256 for part in parts[:3])

lista_IP = get_all_ips()
print('Seus IPs versão 4 são:', colored(lista_IP, attrs=['bold']))

def levantamento_de_dados():
    print("""
    Hora de selecionar um ou mais host(s)
    Informe a sub-rede usando a notação CIDR no final do IPv4 caso queira analisar toda a rede

    Legenda de classes
    Classe A sub-rede 255.0.0.0 = /8 
    Classe B sub-rede 255.255.0.0 = /16 
    Classe C sub-rede 255.255.255.0 = /24
    """)

    # Seleciona um conjunto menor de portas para análise
    portasSelecionadas = "20-23,42,43,69,80,109,110,115,118,143,144,156,161,162,179,220,386,389,443,465,513,514,530,547,587,636,873,989,990,993,995,1080,1194,1433,1521,2049,2081,2083,2086,2181,3306,3389,5353,5432,8080"
    while True:
        alvo = input('Informe o(s) host(s) aqui: ')
        if validaIPv4(alvo):
            print('\nDeseja escolher a(s) porta(s) que vão ser analisadas? Em caso negativo, a análise vai selecionar as portas de serviços mais frequentes')
            verPort = input('S para sim ou N para não\n')
            if verPort.lower() == 's' or verPort.lower() == 'n':
                if verPort.lower() == 's':
                    print("""\n
### Siga um dos exemplos ###

Unica porta
    8080 

2 ou mais portas especificas
    443,8080

Range de portas do 0 a 5000
    0-5000
""")
                    portasSelecionadas = input('\nPasse a(s) porta(s) de interesse\n')
                    if portasSelecionadas != "":
                        return alvo, portasSelecionadas
                elif verPort.lower() == 'n':
                    return alvo, portasSelecionadas
            else:
                print(colored("\n### Resposta invalida na passagem de parametros, digite uma resposta válida para prosseguir ###", 'red'))
        else:
            print(colored("IP informado inválido", 'red'))

def fazer_scan(alvo, portasSelecionadas):
    inicio_Scan = time.time()
    print("Analise iniciada, aguarde o processamento")
    analise = nmap.PortScanner()

    # Parâmetros para detecção de SO, usando escaneamento do tipo SYN exi
    result = analise.scan(alvo, portasSelecionadas, '-A -sS --osscan-guess --min-rate=50000 -T3')

    #Parte que exibe no terminal
    print("--------------------------------------------------")
    print(colored("***HOST(S) CONECTADOS***", 'white', attrs=['bold']))
    print("Numero total: ", len(result['scan']))
    print()
    for cont, cada in enumerate(result['scan'], start=1):
        print(colored(f"ID: {cont}", attrs=['bold']))
        print(colored(f"IP: {cada}", attrs=['bold']))
        tcp_info = result['scan'][cada].get('tcp', {})
        if tcp_info:
            print("Resultado de consulta usando protocolo TCP")
            for porta, porta_info in tcp_info.items():
                print(colored(f"Porta reconhecida: {porta} / Reaçao - {porta_info.get('reason', 'Desconhecido')}", attrs=['bold']))
                servico = porta_info.get('name')
                if servico:
                    print(colored(f"   Serviço rodando na porta {porta}: {servico}", attrs=['bold']))
                else:
                    print(colored("   Serviço: Falha ao obter", 'yellow'))

        else:
            print(colored("Portas reconhecidas: 0",attrs=['bold']))

        mac = result['scan'][cada].get('addresses', {}).get('mac', colored('Falha ao obter', 'yellow'))
        print(colored(f"MAC: {mac}", attrs=['bold']))
        vendor = result['scan'][cada].get('vendor', {})
        if vendor:
            for fab in vendor:
                print(colored(f"Fabricante: {vendor[fab]}", attrs=['bold']))
        else:
            print(colored("Fabricante: ", attrs=['bold']), colored('Falha ao obter','yellow', attrs=['bold']))

        reacao = result['scan'][cada].get('status', {}).get('reason', colored('Falha ao obter', 'yellow', attrs=['bold']))
        print(colored(f"Meio de resposta: {reacao}", attrs=['bold']))
        sistema_operacional = result['scan'][cada].get('osmatch', [])
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

    for cont, cada in enumerate(result['scan'], start=1):
        output_file.write("ID: " + str(cont) + "\n")
        output_file.write("IP: " + cada + "\n")
        tcp_info = result['scan'][cada].get('tcp', {})
        if tcp_info:
            output_file.write("Resultado de consulta usando protocolo TCP\n")
            for porta, porta_info in tcp_info.items():
                output_file.write("Porta reconhecida: " + str(porta) + " / Reação - " + str(porta_info.get('reason', 'Desconhecido')) + "\n")
                servico = porta_info.get('name')
                if servico:
                    output_file.write("   Serviço rodando na porta " + str(porta) + ": " + servico + "\n")
                else:
                    output_file.write("   Serviço: Falha ao obter\n")

        else:
            output_file.write("Portas reconhecidas: 0\n")

        mac = result['scan'][cada].get('addresses', {}).get('mac', 'Falha ao obter')
        output_file.write("MAC: " + str(mac) + "\n")
        vendor = result['scan'][cada].get('vendor', {})
        if vendor:
            for fab in vendor:
                output_file.write("Fabricante: " + vendor[fab] + "\n")
        else:
            output_file.write("Fabricante: Falha ao obter\n")

        reacao = result['scan'][cada].get('status', {}).get('reason', 'Falha ao obter')
        output_file.write("Meio de resposta: " + str(reacao) + "\n")
        sistema_operacional = result['scan'][cada].get('osmatch', [])
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
            retorno = levantamento_de_dados()
            alvoG, portasSelecionadasG = retorno
            start_time = time.time()
            fazer_scan(alvoG, portasSelecionadasG)
        except:
            print(colored("\nFinalizaçao manual executada", "red"))

        elapsed_time = time.time() - start_time
        if elapsed_time and elapsed_time < 2:
            print(colored('\n### Houve um erro no processamento das entradas, revise-as e tente novamente ###\n', 'red'))
        else:
            break
