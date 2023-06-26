#TODO: Adicionar docstring

from abc import ABC
from scapy.all import IP, TCP, UDP, ICMP, RandMAC, Ether, RandIP, get_if_hwaddr


class AbstractPacket(ABC):
    #TODO: Adicionar docstring
    
    def packet_builder(self):
        host_ip = self.host_ip_input()
        host_port = self.host_port_input(host_ip)
        chosen_layer = self.get_layer(host_port)
        payload = self.payload_input()
                
        use_rand_mac_and_ip = input("Want to use random MAC and IP address? (Y for yes): ").upper() == 'Y'
        
        if not use_rand_mac_and_ip:
            ether_layer = Ether(src=get_if_hwaddr('wlxf4ec38924d47'))
            ip_layer = IP(dst=host_ip)
        else:        
            ether_layer = Ether(src=RandMAC())
            ip_layer = IP(dst=host_ip, src=RandIP())

        packet = ether_layer / ip_layer / chosen_layer / payload

        return packet

    def host_ip_input(self): #TODO: Listar ip dos aparelhos na rede para seleção - Usar PortScanner
        #TODO: Adicionar docstring
                
        host_ip = input('Enter the IP address of the destination host: ')
                
        return host_ip
    
    def host_port_input(self, host_ip): #TODO: Listar portas abertas para seleção - Usar PortScanner
        #TODO: Adicionar docstring

        host_port = int(input('Enter the destination port: '))
        return host_port

    def payload_input(self):
        #TODO: Adicionar docstring

        payload = input('Enter a payload to be in the package: ')
        return payload

    def get_layer(self, host_port):
        #TODO: Adicionar docstring

        raise NotImplementedError


class TCPPacket(AbstractPacket):
    #TODO: Adicionar docstring

    def get_layer(self, host_port): #TODO: verificar possiveis excessões
        #TODO: Adicionar docstring

        return TCP(dport=host_port)


class UDPPacket(AbstractPacket):
    #TODO: Adicionar docstring

    def get_layer(self, host_port): #TODO: verificar possiveis excessões
        #TODO: Adicionar docstring

        return UDP(dport=host_port)


class ICMPPacket(AbstractPacket):
    #TODO: Adicionar docstring

    def host_port_input(self, host_ip):
        #TODO: Adicionar docstring

        return ''

    def get_layer(self, host_port): #TODO: verificar possiveis excessões
        #TODO: Adicionar docstring

        return ICMP()