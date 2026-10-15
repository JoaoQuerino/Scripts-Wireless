import datetime
import time

from scapy.all import IP, sniff
from scapy.error import Scapy_Exception
from tabulate import tabulate

from anomaly_monitor_files.anomaly_monitor_utils import plot_reading_data, save_alert
from printer import FontTypes, formater_text, f_print
from user_input import host_ip_input, get_user_input_generic, get_save_option, get_interface


def get_positive_integer(prompt):
    """Ask for a positive integer that can also be used as a timeout."""
    while True:
        value = get_user_input_generic(prompt, 'Enter a valid integer.')
        try:
            if value > 0 and float(value) < float('inf'):
                return value
        except OverflowError:
            pass
        f_print(formater_text('Enter a positive integer within the supported range.', FontTypes.ALERT))


def capture_packet_counts(monitored_ip, interface, timeout):
    """Count incoming IPv4 packets by source for one analysis interval."""
    packets_by_source = {}

    def packet_handler(packet):
        if packet.haslayer(IP) and packet[IP].dst == monitored_ip:
            source_ip = packet[IP].src
            packets_by_source[source_ip] = packets_by_source.get(source_ip, 0) + 1

    sniff(
        prn=packet_handler,
        filter=f'ip dst host {monitored_ip}',
        iface=interface,
        timeout=timeout,
        store=False,
        chainCC=True,
    )
    return packets_by_source


def monitor_traffic(monitored_ip, maximum_to_alert, interval_seconds, duration, interface, save_path=None):
    """Display each reading and optionally save alerts until time runs out."""
    readings = []
    packet_counts = []
    average_counts = []
    received_total = 0
    stop_time = time.monotonic() + duration
    headers = ['READING', 'IP DST', 'RECEIVED PACKETS', 'SUSPECTS (IP: PACKETS)', 'ALERT LIMIT', 'READING TIME']

    while True:
        remaining_seconds = stop_time - time.monotonic()
        if remaining_seconds <= 0:
            break

        capture_seconds = min(interval_seconds, remaining_seconds)
        try:
            packets_by_source = capture_packet_counts(monitored_ip, interface, capture_seconds)
        except KeyboardInterrupt:
            f_print('Monitoring stopped by the user.')
            break
        except (OSError, Scapy_Exception, ValueError, OverflowError) as error:
            f_print(formater_text(f'Capture failed: {error}', FontTypes.ERROR))
            break

        received_count = sum(packets_by_source.values())
        suspects = ', '.join(
            f'{source_ip}: {count}'
            for source_ip, count in sorted(packets_by_source.items())
            if count >= maximum_to_alert
        ) or 'No suspect'
        reading_number = len(readings) + 1
        reading_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        row = [reading_number, monitored_ip, received_count, suspects, maximum_to_alert, reading_time]
        table = tabulate([row], headers=headers, tablefmt='grid')
        is_alert = received_count >= maximum_to_alert
        f_print(formater_text(table, FontTypes.ERROR) if is_alert else table)

        received_total += received_count
        readings.append(reading_number)
        packet_counts.append(received_count)
        average_counts.append(received_total / reading_number)

        if is_alert and save_path is not None:
            try:
                save_alert(save_path, [monitored_ip, suspects, received_count, capture_seconds, maximum_to_alert, reading_time])
            except (OSError, ValueError, UnicodeError) as error:
                f_print(formater_text(f'Could not save the alert: {error}. Saving disabled; monitoring continues.', FontTypes.ERROR))
                save_path = None

    if readings:
        plot_reading_data(readings, average_counts, packet_counts)


def main():
    """Read monitoring options without running prompts when imported."""
    try:
        monitored_ip = host_ip_input()
        maximum_to_alert = get_positive_integer('Enter the packet count that triggers an alert: ')
        interval_seconds = get_positive_integer('Enter the interval between analyses in seconds: ')
        duration = get_positive_integer('Enter the execution duration in seconds: ')
        interface = get_interface()
        save_path = get_save_option()
        monitor_traffic(monitored_ip, maximum_to_alert, interval_seconds, duration, interface, save_path)
    except (KeyboardInterrupt, EOFError):
        f_print('Monitoring stopped by the user.')
    except Exception as error:
        # Stop once on an unexpected failure instead of repeating a broken loop.
        f_print(formater_text(f'Monitoring stopped ({type(error).__name__}): {error}', FontTypes.ERROR))


if __name__ == '__main__':
    main()
