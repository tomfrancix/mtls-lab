"""CLI entry point: python main.py setup | list | run NAME | all | inspect NAME"""
from __future__ import annotations
import argparse
import subprocess
from pathlib import Path
from lab.certificates import generate
from lab.scenarios import SCENARIOS
from lab.transport import execute

ROOT = Path(__file__).resolve().parent
PKI = ROOT / '.generated' / 'pki'


def main() -> int:
    parser = argparse.ArgumentParser(description='Real mutual TLS failure laboratory')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('setup', help='Generate local test certificates (replaces existing PKI)')
    sub.add_parser('list', help='List independent failure scenarios')
    run = sub.add_parser('run', help='Run one scenario')
    run.add_argument('name', choices=sorted(SCENARIOS))
    sub.add_parser('all', help='Run all scenarios independently')
    inspect = sub.add_parser('inspect', help='Inspect a generated X.509 certificate')
    inspect.add_argument('name', choices=['trusted-ca', 'rogue-ca', 'server', 'client', 'rogue-client', 'rogue-server', 'wrong-host-server', 'wrong-eku-client', 'wrong-eku-server', 'expired-client'])
    args = parser.parse_args()
    if args.command == 'setup':
        generate(PKI)
        print(f'Generated isolated test PKI: {PKI}')
        return 0
    if args.command == 'list':
        for name, scenario in SCENARIOS.items():
            print(f'{name:29} {scenario.explanation}')
        return 0
    if not PKI.joinpath('trusted-ca.crt').exists():
        parser.error('Run `python main.py setup` first.')
    if args.command == 'inspect':
        return subprocess.call(['openssl', 'x509', '-in', str(PKI / f'{args.name}.crt'), '-noout', '-text'])
    names = [args.name] if args.command == 'run' else list(SCENARIOS)
    unexpected = 0
    for name in names:
        scenario = SCENARIOS[name]
        result = execute(PKI, scenario.config)
        succeeded = result.response.startswith('HTTP/1.0 200 OK')
        matched = succeeded == scenario.expected_success
        unexpected += not matched
        print(f'\n{"=" * 75}\n{name} | {"PASS" if matched else "UNEXPECTED"} | connection={"SUCCESS" if succeeded else "FAILED"}')
        print(f'Cause: {scenario.explanation}')
        print(f'Client: {result.client}\nServer: {result.server}')
        if result.tls_version:
            print(f'Negotiated: {result.tls_version} {result.cipher}')
            print(f'Client sees server identity: {result.client_peer}')
            print(f'Server sees client identity: {result.server_peer}')
        if result.response:
            print(f'HTTP: {result.response.splitlines()[0]}')
        if not matched:
            print('WARNING: Actual result differed from expected. Inspect both endpoints and OpenSSL version.')
    return 1 if unexpected else 0


if __name__ == '__main__':
    raise SystemExit(main())
