import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scapy.all import IP, ARP

import anomaly_monitor as monitor
from anomaly_monitor_files.anomaly_monitor_utils import save_alert
from user_input import get_save_option


class AnomalyMonitorTests(unittest.TestCase):
    def test_counts_only_destination_and_resets_each_interval(self):
        packets = [IP(src='192.0.2.1', dst='192.0.2.2')] * 2
        packets += [IP(src='192.0.2.1', dst='192.0.2.3'), ARP()]

        def capture(**options):
            self.assertFalse(options['store'])
            self.assertTrue(options['chainCC'])
            for packet in packets:
                options['prn'](packet)

        with patch.object(monitor, 'sniff', side_effect=capture):
            for _ in range(2):
                self.assertEqual(monitor.capture_packet_counts('192.0.2.2', 'test', 1), {'192.0.2.1': 2})

    def test_alert_at_limit_and_final_interval_is_shortened(self):
        with patch.object(monitor.time, 'monotonic', side_effect=[0, 0, 2, 3]), \
             patch.object(monitor, 'capture_packet_counts', side_effect=[{'192.0.2.1': 2}, {}]) as capture, \
             patch.object(monitor, 'save_alert') as save, \
             patch.object(monitor, 'f_print') as output, \
             patch.object(monitor, 'plot_reading_data') as plot:
            monitor.monitor_traffic('192.0.2.2', 2, 2, 3, 'test', 'alerts.csv')
            self.assertEqual([call.args[2] for call in capture.call_args_list], [2, 1])
            save.assert_called_once()
            self.assertEqual(save.call_args.args[1][1:3], ['192.0.2.1: 2', 2])
            self.assertIn('192.0.2.1: 2', output.call_args_list[0].args[0])
            self.assertIn('No suspect', output.call_args_list[1].args[0])
            plot.assert_called_once_with([1, 2], [2.0, 1.0], [2, 0])

    def test_saving_disabled_does_not_write(self):
        with patch.object(monitor.time, 'monotonic', side_effect=[0, 0, 1]), \
             patch.object(monitor, 'capture_packet_counts', return_value={'192.0.2.1': 2}), \
             patch.object(monitor, 'save_alert') as save, \
             patch.object(monitor, 'f_print'), \
             patch.object(monitor, 'plot_reading_data'):
            monitor.monitor_traffic('192.0.2.2', 2, 1, 1, 'test', None)
            save.assert_not_called()

    def test_save_failure_disables_saving_and_continues(self):
        with patch.object(monitor.time, 'monotonic', side_effect=[0, 0, 1, 2]), \
             patch.object(monitor, 'capture_packet_counts', return_value={'192.0.2.1': 2}) as capture, \
             patch.object(monitor, 'save_alert', side_effect=PermissionError('denied')) as save, \
             patch.object(monitor, 'f_print'), \
             patch.object(monitor, 'plot_reading_data') as plot:
            monitor.monitor_traffic('192.0.2.2', 2, 1, 2, 'test', 'alerts.csv')
            save.assert_called_once()
            self.assertEqual(capture.call_count, 2)
            plot.assert_called_once_with([1, 2], [2.0, 2.0], [2, 2])

    def test_capture_error_or_interrupt_stops_without_empty_plot(self):
        for error in [PermissionError('denied'), monitor.Scapy_Exception('capture failed'), KeyboardInterrupt()]:
            with self.subTest(error=type(error).__name__), \
                 patch.object(monitor.time, 'monotonic', side_effect=[0, 0]), \
                 patch.object(monitor, 'capture_packet_counts', side_effect=error) as capture, \
                 patch.object(monitor, 'f_print'), \
                 patch.object(monitor, 'plot_reading_data') as plot:
                monitor.monitor_traffic('192.0.2.2', 2, 1, 2, 'test')
                capture.assert_called_once()
                plot.assert_not_called()

    def test_positive_input_retries_invalid_values(self):
        with patch('builtins.input', side_effect=['abc', '0', '-1', '2']), patch.object(monitor, 'f_print'):
            self.assertEqual(monitor.get_positive_integer('Value: '), 2)

    def test_save_option_returns_none(self):
        with patch('builtins.input', side_effect=[' N ']):
            self.assertIsNone(get_save_option())

    def test_save_option_retries_invalid_choice_and_filename(self):
        with patch('builtins.input', side_effect=['invalid', 'y', '', '.', 'bad\x00name', 'alerts.csv']), \
             patch('user_input.f_print'):
            self.assertEqual(Path(get_save_option()).name, 'alerts.csv')

    def test_log_header_is_not_duplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'alerts.csv'
            row = ['192.0.2.2', '192.0.2.1: 2', 2, 1, 2, '2026-10-14 12:00:00']
            save_alert(path, row)
            save_alert(path, row)
            with path.open(newline='', encoding='utf-8') as log_file:
                rows = list(csv.reader(log_file, delimiter=';'))
            self.assertEqual(len(rows), 3)
            self.assertEqual(rows[0][0], 'Destiny')
            self.assertEqual(rows[1], rows[2])

    def test_save_alert_none_does_not_open_file(self):
        with patch('builtins.open') as open_file:
            save_alert(None, [])
            open_file.assert_not_called()


if __name__ == '__main__':
    unittest.main()
