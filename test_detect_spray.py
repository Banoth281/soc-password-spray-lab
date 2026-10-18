import csv
import tempfile
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from detect_spray import detect, read_events


def event(account, seconds, source='198.51.100.25', result='failure'):
    return {'account': account, 'timestamp': datetime(2026, 10, 5, tzinfo=timezone.utc)
            + timedelta(seconds=seconds), 'source_ip': source, 'result': result}


class DetectionTests(unittest.TestCase):
    def test_five_accounts_and_unsorted_events(self):
        alerts = detect([event(str(i), i * 30) for i in reversed(range(5))])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['distinct_accounts'], 5)

    def test_repeated_single_account(self):
        self.assertEqual(detect([event('alice', i) for i in range(10)]), [])

    def test_sources_are_separate(self):
        self.assertEqual(detect([event(str(i), i, f'198.51.100.{i}') for i in range(5)]), [])

    def test_inclusive_boundary(self):
        self.assertEqual(len(detect([event(str(i), i * 75) for i in range(5)])), 1)

    def test_expired_failure_excluded(self):
        self.assertEqual(detect([event(str(i), i * 76) for i in range(5)]), [])

    def test_success_not_counted(self):
        rows = [event(str(i), i) for i in range(4)] + [event('fifth', 5, result='success')]
        self.assertEqual(detect(rows), [])

    def test_suppression_and_new_episode(self):
        rows = [event(str(i), i) for i in range(6)]
        rows += [event(str(i), 600 + i) for i in range(5)]
        self.assertEqual(len(detect(rows)), 2)

    def test_invalid_rows_reported(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'events.csv'
            path.write_text('timestamp,account,source_ip,result\n'
                            'bad,alice,198.51.100.1,failure\n'
                            '2026-10-05T00:00:00,alice,198.51.100.1,failure\n'
                            '2026-10-05T00:00:00Z,alice,198.51.100.1,failure\n')
            rows, errors = read_events(path)
            self.assertEqual(len(rows), 1)
            self.assertEqual(len(errors), 2)


class ValidationTests(unittest.TestCase):
    def read_csv(self, text):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'input.csv'
            path.write_text(text, encoding='utf-8')
            return read_events(path)

    def test_missing_columns(self):
        with self.assertRaises(ValueError):
            self.read_csv('timestamp,account\n')

    def test_duplicate_headers(self):
        with self.assertRaises(ValueError):
            self.read_csv('timestamp,account,source_ip,result,account\n')

    def test_duplicate_normalised_event(self):
        rows, errors = self.read_csv('timestamp,account,source_ip,result\n'
            '2026-10-05T00:00:00Z,alice,198.51.100.1,failure\n'
            '2026-10-05T01:00:00+01:00,alice,198.51.100.1,FAILURE\n')
        self.assertEqual(len(rows), 1)
        self.assertEqual(errors[0]['line'], 3)
        self.assertIn('Duplicate', errors[0]['error'])

    def test_missing_and_extra_fields(self):
        rows, errors = self.read_csv('timestamp,account,source_ip,result\n'
            '2026-10-05T00:00:00Z,alice,198.51.100.1\n'
            '2026-10-05T00:00:00Z,alice,198.51.100.1,failure,extra\n')
        self.assertEqual(rows, [])
        self.assertEqual([e['line'] for e in errors], [2, 3])

    def test_invalid_ip_account_and_result(self):
        rows, errors = self.read_csv('timestamp,account,source_ip,result\n'
            '2026-10-05T00:00:00Z,alice,not-an-ip,failure\n'
            '2026-10-05T00:00:00Z,,198.51.100.1,failure\n'
            '2026-10-05T00:00:00Z,alice,198.51.100.1,unknown\n')
        self.assertEqual(rows, [])
        self.assertEqual(len(errors), 3)

    def test_multiline_physical_line_reporting(self):
        _, errors = self.read_csv('timestamp,account,source_ip,result\n'
            'bad,"multi\nline",198.51.100.1,failure\n')
        self.assertEqual(errors[0]['line'], 3)

    def test_empty_events(self):
        self.assertEqual(detect([]), [])

    def test_invalid_parameters(self):
        for threshold, minutes in [(1, 5), (5, 0), (5, -1)]:
            with self.subTest(threshold=threshold, minutes=minutes):
                with self.assertRaises(ValueError):
                    detect([], threshold, minutes)

    def test_cli_preserves_input(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'input.csv'
            original = 'timestamp,account,source_ip,result\n'
            path.write_text(original)
            process = subprocess.run([sys.executable,
                str(Path(__file__).with_name('detect_spray.py')),
                '--input', str(path), '--output', str(path)],
                capture_output=True, text=True)
            self.assertNotEqual(process.returncode, 0)
            self.assertIn('must not overwrite', process.stderr)
            self.assertEqual(path.read_text(), original)

    def test_checked_in_sample_report(self):
        import json
        folder = Path(__file__).resolve().parent
        rows, errors = read_events(folder / 'login_events.csv')
        actual = {'valid_events': len(rows), 'rejected_rows': errors,
                  'alerts': detect(rows)}
        expected = json.loads((folder / 'alerts.json').read_text())
        self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()

