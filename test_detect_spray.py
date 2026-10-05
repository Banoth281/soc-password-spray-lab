import csv
import tempfile
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


if __name__ == '__main__':
    unittest.main()
