#!/usr/bin/env python3
"""Local, manual acceptance evidence ledger; never installs or sends evidence.

Hashes bind reviewed evidence to a declared build. They do not certify that a
log is truthful, or prove which source was compiled; reviewers check provenance.
"""
import argparse
import datetime
import hashlib
import itertools
import json
import math
from pathlib import Path
import re
import sys

SCHEMA = 1
STATUSES = ('passed', 'failed', 'not_run', 'unsupported')
PACKAGE = ('build_provenance', 'clean_install', 'permissions_service', 'uninstall_restore',
           'publisher_signature', 'signed_update_metadata', 'update_vault_guard',
           'rollback_vault_guard')
BUDGETS = ('recovery_seconds', 'soak_hours', 'max_rss_mib', 'max_cpu_percent',
           'max_battery_percent_hour')
NETWORK = ('dns_failure', 'ipv4_ipv6_dns_https', 'cold_boot', 'sleep_wake',
           'network_handoff', 'gui_crash', 'service_crash', 'endpoint_outage',
           'forbidden_egress', 'stop_owned_state_restore', 'recovery_timing',
           'soak_resources_battery')


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def identity(path):
    path = path.resolve(strict=True)
    if not path.is_file():
        raise ValueError('Artifact/evidence must be a regular file')
    return {'path': str(path), 'sha256': digest(path), 'size': path.stat().st_size}


def cells(protocols, modes):
    for labels in (protocols, modes):
        if (not isinstance(labels, list) or not labels
                or any(not isinstance(label, str) or
                       not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', label) for label in labels)
                or len(set(labels)) != len(labels)):
            raise ValueError('Use unique nonempty protocol/mode identifiers without slashes')
    return list(PACKAGE) + [f'{protocol}/{mode}/{scenario}'
                           for protocol, mode, scenario in
                           itertools.product(protocols, modes, NETWORK)]


def write(path, data):
    # A ledger is mutable until reviewed; refuse accidental replacement on init.
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n')


def init(args):
    if args.output.exists():
        raise ValueError('Ledger already exists; use another output file')
    if any(not getattr(args, field).strip() for field in
           ('version', 'platform', 'device', 'os_version', 'owner')):
        raise ValueError('Source/package/device identity and owner cannot be empty')
    if not re.fullmatch(r'[0-9a-f]{40}', args.commit):
        raise ValueError('Use the full 40-character source commit')
    if len(set(args.protocol)) != len(args.protocol) or len(set(args.mode)) != len(args.mode):
        raise ValueError('Duplicate protocol/mode')
    budgets = (args.soak_hours, args.recovery_seconds, args.max_rss_mib,
               args.max_cpu_percent, args.max_battery_percent_hour)
    if args.soak_hours < 24 or any(not math.isfinite(value) or value <= 0 for value in budgets):
        raise ValueError('Set positive budgets before running; soak must be at least 24 hours')
    data = {'schema': SCHEMA, 'created_at': now(), 'commit': args.commit,
            'version': args.version, 'platform': args.platform, 'device': args.device,
            'os_version': args.os_version, 'protocols': args.protocol, 'modes': args.mode,
            'artifacts': [identity(item) for item in args.artifact],
            'criteria': {'recovery_seconds': args.recovery_seconds,
                         'soak_hours': args.soak_hours, 'max_rss_mib': args.max_rss_mib,
                         'max_cpu_percent': args.max_cpu_percent,
                         'max_battery_percent_hour': args.max_battery_percent_hour},
            'results': {case: {'status': 'not_run', 'owner': args.owner,
                               'reason': 'Awaiting exact-package test', 'evidence': []}
                        for case in cells(args.protocol, args.mode)}}
    write(args.output, data)


def load(path, commit):
    data = json.loads(path.read_text())
    if data.get('schema') != SCHEMA or data.get('commit') != commit:
        raise ValueError('Ledger schema/source commit mismatch')
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('Invalid commit')
    for field in ('version', 'platform', 'device', 'os_version'):
        if not isinstance(data.get(field), str) or not data[field].strip():
            raise ValueError(f'Missing identity: {field}')
    protocols, modes = data['protocols'], data['modes']
    if (not protocols or not modes or len(set(protocols)) != len(protocols)
            or len(set(modes)) != len(modes)):
        raise ValueError('Missing/duplicate protocol or mode')
    expected = set(cells(protocols, modes))
    if set(data['results']) != expected:
        raise ValueError('Incomplete or unexpected acceptance cases')
    if not data['artifacts']:
        raise ValueError('No package artifacts')
    for item in data['artifacts']:
        if identity(Path(item['path'])) != item:
            raise ValueError('Package hash/size/path changed')
    for case, result in data['results'].items():
        if result['status'] not in STATUSES or not result.get('owner', '').strip() or not result.get('reason', '').strip():
            raise ValueError(f'Invalid result: {case}')
        if result['status'] in ('passed', 'failed'):
            if not result.get('recorded_at') or not result['evidence']:
                raise ValueError(f'Missing timestamp/evidence: {case}')
        for item in result['evidence']:
            if identity(Path(item['path'])) != item:
                raise ValueError(f'Evidence hash/size/path changed: {case}')
    criteria = data['criteria']
    if set(criteria) != set(BUDGETS):
        raise ValueError('Incomplete or unexpected acceptance budgets')
    if criteria['soak_hours'] < 24 or any(not math.isfinite(value) or value <= 0
                                            for value in criteria.values()):
        raise ValueError('Invalid predeclared acceptance budgets')
    return data


def record(args):
    if not args.owner.strip() or not args.reason.strip():
        raise ValueError('A reviewed result requires an owner and reason')
    data = load(args.ledger, args.commit)
    if args.case not in data['results']:
        raise ValueError('Unknown acceptance case')
    if args.status in ('passed', 'failed') and not args.evidence:
        raise ValueError('Passed/failed results require reviewed evidence files')
    data['results'][args.case] = {'status': args.status, 'owner': args.owner,
                                'reason': args.reason, 'recorded_at': now(),
                                'evidence': [identity(item) for item in args.evidence]}
    write(args.ledger, data)


def verify(args):
    data = load(args.ledger, args.commit)
    counts = {status: sum(row['status'] == status for row in data['results'].values())
              for status in STATUSES}
    complete = counts['passed'] == len(data['results'])
    print(json.dumps({'commit': data['commit'], 'platform': data['platform'],
                      'version': data['version'], 'counts': counts,
                      'all_required_cases_passed': complete,
                      'release_promotion_authorized': False}, indent=2))
    return 0 if complete or not args.require_passed else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    start = sub.add_parser('init')
    start.add_argument('--output', type=Path, required=True)
    for field in ('commit', 'version', 'platform', 'device', 'os-version', 'owner'):
        start.add_argument('--' + field, required=True)
    start.add_argument('--artifact', type=Path, action='append', required=True)
    start.add_argument('--protocol', action='append', required=True)
    start.add_argument('--mode', action='append', required=True)
    start.add_argument('--recovery-seconds', type=float, required=True)
    start.add_argument('--soak-hours', type=float, default=24)
    start.add_argument('--max-rss-mib', type=float, required=True)
    start.add_argument('--max-cpu-percent', type=float, required=True)
    start.add_argument('--max-battery-percent-hour', type=float, required=True)
    for command in ('record', 'verify'):
        operation = sub.add_parser(command)
        operation.add_argument('--ledger', type=Path, required=True)
        operation.add_argument('--commit', required=True)
        if command == 'record':
            operation.add_argument('--case', required=True)
            operation.add_argument('--status', choices=STATUSES, required=True)
            operation.add_argument('--owner', required=True)
            operation.add_argument('--reason', required=True)
            operation.add_argument('--evidence', type=Path, action='append', default=[])
        else:
            operation.add_argument('--require-passed', action='store_true')
    args = parser.parse_args(argv)
    try:
        return {'init': init, 'record': record, 'verify': verify}[args.command](args) or 0
    except (ValueError, OSError, KeyError, TypeError, AttributeError) as error:
        print(f'Acceptance ledger rejected: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
