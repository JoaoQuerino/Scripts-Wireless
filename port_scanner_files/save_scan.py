
def save_to_file(result):
    nameArq = get_filename()
    content = generate_file_content(result)
    write_to_file(nameArq, content)
    print(f"Resultado da analise salvo como '{nameArq}.txt', ele esta salvo na pasta localizada o script")

def get_filename():
    return input('\nInforme o nome do arquivo para salvamento da leitura:\n')

def write_to_file(filename, content):
    with open(f"{filename}.txt", "w") as output_file:
        output_file.write(content)

def generate_file_content(result):
    content = ''
    content += "*** HOST(S) CONECTADOS ***\n"
    content += "Numero total: " + str(len(result['scan'])) + "\n\n"
    device_counter = 1

    for cont, device_ip in enumerate(result['scan'], start=1):
        content += generate_device_info(device_counter, device_ip, result['scan'][device_ip])
        device_counter += 1

    return content

def generate_device_info(device_id, device_ip, device_info):
    content = f"ID: {device_id}\n"
    content += f"IP: {device_ip}\n"
    content += generate_tcp_info(device_info.get('tcp', {}))
    content += generate_mac_info(device_info.get('addresses', {}).get('mac', 'Falha ao obter'))
    content += generate_vendor_info(device_info.get('vendor', {}))
    content += generate_response_info(device_info.get('status', {}).get('reason', 'Falha ao obter'))
    content += generate_operating_system_info(device_info.get('osmatch', []))
    content += "\n"
    return content

def generate_tcp_info(tcp_info):
    content = ""
    if tcp_info:
        content += "Query result using TCP protocol\n"
        for port, port_info in tcp_info.items():
            content += f"Recognized port: {port} / Reason - {port_info.get('reason', 'unknow')}\n"
            service = port_info.get('name')
            if service:
                content += f"   Service running on the port {port}: {service}\n"
            else:
                content += "   Service: unknow\n"
    else:
        content += "Portas reconhecidas: 0\n"
    return content

def generate_mac_info(mac):
    return f"MAC: {mac}\n"

def generate_vendor_info(vendor):
    content = ""
    if vendor:
        for fab in vendor:
            content += f"Producer: {vendor[fab]}\n"
    else:
        content += "Producer: unknow\n"
    return content

def generate_response_info(reacao):
    return f"Answer type: {reacao}\n"

def generate_operating_system_info(sistema_operacional):
    content = ""
    if sistema_operacional:
        content += f"Operational system:: {sistema_operacional[0]['name']}\n"
    else:
        content += "Operational system: unknow\n"
    return content