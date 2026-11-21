"""Generate isolated test PKI using the installed OpenSSL CLI."""
from __future__ import annotations
import subprocess
from pathlib import Path


def run(*args: str) -> None:
    process = subprocess.run(['openssl', *args], capture_output=True, text=True)
    if process.returncode:
        raise RuntimeError(f"OpenSSL failed: {' '.join(args)}\n{process.stderr}")


def generate(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    def ca(name: str) -> None:
        run('req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes',
            '-days', '365', '-subj', f'/CN={name}', '-keyout', str(directory / f'{name}.key'),
            '-out', str(directory / f'{name}.crt'), '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    ca('trusted-ca')
    ca('rogue-ca')

    def leaf(name: str, issuer: str, eku: str, *, days: int = 30, hostname: str = 'localhost') -> None:
        key = directory / f'{name}.key'
        csr = directory / f'{name}.csr'
        cert = directory / f'{name}.crt'
        ext = directory / f'{name}.ext'
        ext.write_text('basicConstraints=critical,CA:FALSE\n'
                       'keyUsage=critical,digitalSignature,keyEncipherment\n'
                       f'extendedKeyUsage={eku}\n'
                       f'subjectAltName=DNS:{hostname}\n', encoding='utf-8')
        run('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256',
            '-subj', f'/CN={name}', '-keyout', str(key), '-out', str(csr))
        run('x509', '-req', '-in', str(csr), '-CA', str(directory / f'{issuer}.crt'),
            '-CAkey', str(directory / f'{issuer}.key'), '-CAcreateserial',
            '-out', str(cert), '-days', str(days), '-sha256', '-extfile', str(ext))

    leaf('server', 'trusted-ca', 'serverAuth')
    leaf('client', 'trusted-ca', 'clientAuth')
    leaf('rogue-client', 'rogue-ca', 'clientAuth')
    leaf('rogue-server', 'rogue-ca', 'serverAuth')
    leaf('wrong-host-server', 'trusted-ca', 'serverAuth', hostname='different.example')
    leaf('wrong-eku-client', 'trusted-ca', 'serverAuth')
    leaf('wrong-eku-server', 'trusted-ca', 'clientAuth')
    # OpenSSL -days 0 produces a certificate with notAfter at issuance time.
    # To make expiration deterministic, explicitly replace validity dates via openssl ca.
    generate_expired(directory)


def generate_expired(directory: Path) -> None:
    name = 'expired-client'
    key = directory / f'{name}.key'
    csr = directory / f'{name}.csr'
    cert = directory / f'{name}.crt'
    config = directory / 'expired-ca.cnf'
    database = directory / 'index.txt'
    config_directory = directory.resolve().as_posix()
    database.write_text('', encoding='utf-8')
    (directory / 'serial').write_text('1000\n', encoding='utf-8')
    config.write_text(f'''[ ca ]
default_ca = CA_default
[ CA_default ]
dir = {config_directory}
database = $dir/index.txt
serial = $dir/serial
new_certs_dir = $dir
certificate = $dir/trusted-ca.crt
private_key = $dir/trusted-ca.key
default_md = sha256
policy = policy_any
x509_extensions = leaf_ext
[ policy_any ]
commonName = supplied
[ leaf_ext ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
''', encoding='utf-8')
    run('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256',
        '-subj', f'/CN={name}', '-keyout', str(key), '-out', str(csr))
    run('ca', '-batch', '-config', str(config), '-in', str(csr), '-out', str(cert),
        '-startdate', '20200101000000Z', '-enddate', '20200102000000Z', '-notext')
