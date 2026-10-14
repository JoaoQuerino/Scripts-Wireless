# Scripts-Wireless
Python security script to be used in wireless networks

## Ambiente Python no macOS

Na pasta do projeto, crie e ative o ambiente virtual e instale as dependências:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip check
```

Se `.venv` já estiver instalado, basta ativá-lo com `source .venv/bin/activate`.
Em editores, selecione `.venv/bin/python` como interpretador do projeto.

As dependências Python são Scapy, python-nmap, psutil, Rich, tabulate e Matplotlib.
O pacote `python-nmap` fornece o módulo `nmap`, mas não instala o executável Nmap.
Para usar `port_scanner.py`, instale também o programa Nmap e verifique
`nmap --version`: [instruções oficiais para macOS](https://nmap.org/book/inst-macosx.html).

## Execução

Os scripts que capturam ou enviam pacotes e o scanner com `-sS` podem exigir
privilégios de administrador. Use explicitamente o Python do ambiente virtual:

```sh
sudo .venv/bin/python Sniffer.py
sudo .venv/bin/python anomaly_monitor.py
sudo .venv/bin/python port_scanner.py
sudo .venv/bin/python packet_injection.py
```

Execute apenas o comando correspondente ao script desejado.
Ao iniciar, `Sniffer.py` lista as interfaces de rede reconhecidas pelo Scapy.
Digite o número da interface desejada para usá-la na captura. Entradas inválidas
são solicitadas novamente; se nenhuma interface for encontrada, o script encerra
com uma mensagem explicativa.

A instalação das bibliotecas não corrige eventuais problemas de lógica dos scripts.
