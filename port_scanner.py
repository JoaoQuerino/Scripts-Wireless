import time
import nmap
from printer import FontTypes, formater_text, f_print
from common import get_all_ips
from user_input import get_user_input
from port_scanner_files.save_scan import save_to_file


f_print(formater_text('Welcome\n', FontTypes.BOLD))

list_IP = get_all_ips()
f_print('Your IPv4 are:' + formater_text(list_IP, FontTypes.BOLD))

def start_scan(target_ip_address:str, selected_ports:str):
    f_print(formater_text('Scan started, please wait...', FontTypes.BOLD))
    scanner = nmap.PortScanner()

    start_read_time = time.time()
    result = scanner.scan(target_ip_address, selected_ports, '-A -sS --osscan-guess --min-rate=50000 -T3')
    end_read_time = time.time()

    display_results(result)
    print(f"Processing time: {(end_read_time - start_read_time):.2f}")

    save_to_file(result)
 
def display_results(result:dict): # TODO: Verificar qual o tipo do dicionario e indicar
    print("--------------------------------------------------")
    f_print(formater_text('***HOST LIST***', FontTypes.BOLD))
    print(f'Number of devices: {len(result["scan"])}\n')

    for cont, device_ip in enumerate(result['scan'], start=1):
        display_device_info(cont, device_ip, result['scan'][device_ip])

def display_device_info(cont, device_ip, device_info):
    f_print(formater_text(f'ID: {cont}', FontTypes.BOLD, [1]))
    f_print(formater_text(f'IP: {device_ip}', FontTypes.BOLD, [1]))
    display_tcp_info(device_info.get('tcp', {}))
    display_mac_info(device_info)
    display_vendor_info(device_info.get('vendor', {}))
    display_reaction_info(device_info)
    display_os_info(device_info.get('osmatch', []))
    print()


def display_tcp_info(tcp_info):
    if tcp_info:
        print('Result of search using TCP send')
        for port, port_info in tcp_info.items():
            f_print(formater_text(f'Port found: {port} / Reason - {port_info.get("reason", "unknown")}', FontTypes.BOLD, [2, 3, 4, 5, 6]))
            service = port_info.get('name')
            if service:
                f_print('   Service: running in port' + formater_text(f' {port}: {service}', FontTypes.BOLD))
            else:
                f_print('   Service: ' + formater_text('unknown', FontTypes.ALERT))
    else:
        f_print(formater_text('Ports found: 0', FontTypes.BOLD))

def display_mac_info(device_info):
    mac = device_info.get('addresses', {}).get('mac', formater_text('unknow', FontTypes.ALERT))
    f_print(formater_text(f'MAC: {mac}', FontTypes.NORMAL))

def display_vendor_info(vendor):
   if not vendor:
       f_print(formater_text('Fabricator: ', FontTypes.NORMAL) + formater_text('unknow', FontTypes.ALERT))

   for fabricator in vendor:
        f_print(formater_text(f'Fabricator: {vendor[fabricator]}', FontTypes.BOLD))

def display_reaction_info(device_info):
    reacao = device_info.get('status', {}).get('reason', formater_text('unknow', FontTypes.ALERT))
    f_print("Answer type: " + formater_text(f'{reacao}', FontTypes.NORMAL))

def display_os_info(sistema_operacional):
    if sistema_operacional:
        f_print("Operational system: " + formater_text(f"{sistema_operacional[0]['name']}", FontTypes.BOLD))
    else:
        f_print(formater_text('Operational system: ', FontTypes.NORMAL) + formater_text('unknow', FontTypes.ALERT))

if __name__ == '__main__':
    while True:
        start_time = time.time()
        try:
            user_inputs = get_user_input()
            alvoG, portasSelecionadasG = user_inputs
            start_scan(alvoG, portasSelecionadasG)
        except KeyboardInterrupt:
            f_print(formater_text('\nManual finalization performed', 
                            FontTypes.ERROR))
        # except BaseException as e:
        #     print(e)

        elapsed_time = time.time() - start_time
        if elapsed_time < 2:
            f_print(formater_text('\n### There was an error processing your entries,'\
               'please review and try again ###\n', FontTypes.ERROR))
        else:
            break
        