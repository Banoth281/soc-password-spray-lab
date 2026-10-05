"""Detect multi-account failed authentication patterns in synthetic CSV logs."""
import argparse
import csv
import ipaddress
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path


def read_events(path):
    events, errors = [], []
    with open(path, newline='', encoding='utf-8-sig') as handle:
        reader = csv.DictReader(handle)
        required = {'timestamp', 'account', 'source_ip', 'result'}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError('CSV requires timestamp, account, source_ip, result')
        for line, row in enumerate(reader, 2):
            try:
                stamp = datetime.fromisoformat(row['timestamp'].strip().replace('Z', '+00:00'))
                if stamp.tzinfo is None:
                    raise ValueError('Timestamp must include a timezone')
                account = row['account'].strip()
                source = str(ipaddress.ip_address(row['source_ip'].strip()))
                result = row['result'].strip().lower()
                if not account or result not in {'failure', 'success'}:
                    raise ValueError('Invalid account or result')
                events.append({'timestamp': stamp.astimezone(timezone.utc),
                               'account': account, 'source_ip': source, 'result': result})
            except (ValueError, AttributeError, TypeError) as exc:
                errors.append({'line': line, 'error': str(exc)})
    return sorted(events, key=lambda e: e['timestamp']), errors


def detect(events, threshold=5, window_minutes=5):
    if threshold < 2 or window_minutes <= 0:
        raise ValueError('Threshold must be >= 2 and window must be positive')
    queues = defaultdict(deque)
    active = set()
    alerts = []
    for event in sorted(events, key=lambda e: e['timestamp']):
        source = event['source_ip']
        queue = queues[source]
        cutoff = event['timestamp'] - timedelta(minutes=window_minutes)
        while queue and queue[0]['timestamp'] < cutoff:
            queue.popleft()
        accounts = {item['account'] for item in queue}
        if len(accounts) < threshold:
            active.discard(source)
        if event['result'] != 'failure':
            continue
        queue.append(event)
        accounts.add(event['account'])
        if len(accounts) >= threshold and source not in active:
            alerts.append({'rule': 'multi_account_failures', 'source_ip': source,
                           'window_start': queue[0]['timestamp'].isoformat(),
                           'detected_at': event['timestamp'].isoformat(),
                           'distinct_accounts': len(accounts), 'failed_attempts': len(queue),
                           'accounts': sorted(accounts), 'assessment': 'requires_investigation'})
            active.add(source)
    return alerts


def main():
    folder = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=folder / 'login_events.csv')
    parser.add_argument('--output', type=Path, default=folder / 'alerts.json')
    parser.add_argument('--threshold', type=int, default=5)
    parser.add_argument('--window-minutes', type=int, default=5)
    args = parser.parse_args()
    try:
        events, errors = read_events(args.input)
        report = {'valid_events': len(events), 'rejected_rows': errors,
                  'alerts': detect(events, args.threshold, args.window_minutes)}
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(f"Analysed {len(events)} events; rejected {len(errors)} rows; generated {len(report['alerts'])} alerts.")


if __name__ == '__main__':
    main()
