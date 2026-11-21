"""Actual TLS 1.2+ socket transport, with independent trust configuration."""
from __future__ import annotations
import socket
import ssl
import threading
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Configuration:
    server_cert: str = 'server'
    client_cert: str | None = 'client'
    server_trust: str = 'trusted-ca'
    client_trust: str = 'trusted-ca'
    hostname: str = 'localhost'
    server_requires_client_cert: bool = True
    client_verifies_server: bool = True
    server_minimum: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2
    client_maximum: ssl.TLSVersion = ssl.TLSVersion.MAXIMUM_SUPPORTED


def server_context(pki: Path, config: Configuration) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = config.server_minimum
    context.load_cert_chain(str(pki / f'{config.server_cert}.crt'), str(pki / f'{config.server_cert}.key'))
    context.load_verify_locations(cafile=str(pki / f'{config.server_trust}.crt'))
    context.verify_mode = ssl.CERT_REQUIRED if config.server_requires_client_cert else ssl.CERT_NONE
    return context


def client_context(pki: Path, config: Configuration) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.maximum_version = config.client_maximum
    if config.client_verifies_server:
        context.load_verify_locations(cafile=str(pki / f'{config.client_trust}.crt'))
    else:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if config.client_cert is not None:
        context.load_cert_chain(str(pki / f'{config.client_cert}.crt'), str(pki / f'{config.client_cert}.key'))
    return context


@dataclass
class Result:
    client: str = ''
    server: str = ''
    response: str = ''
    tls_version: str = ''
    cipher: str = ''
    server_peer: str = ''
    client_peer: str = ''


def execute(pki: Path, config: Configuration) -> Result:
    result = Result()
    ready = threading.Event()
    server_finished = threading.Event()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(4)
    port = listener.getsockname()[1]

    def serve() -> None:
        try:
            context = server_context(pki, config)
            ready.set()
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(4)
                with context.wrap_socket(connection, server_side=True) as tls:
                    result.server_peer = str(tls.getpeercert().get('subject', 'none')) if tls.getpeercert() else 'none'
                    request = tls.recv(4096)
                    if request == b'GET /hello HTTP/1.0\r\n\r\n':
                        tls.sendall(b'HTTP/1.0 200 OK\r\nContent-Length: 12\r\n\r\nhello, mTLS!')
                    result.server = 'Handshake accepted; HTTP request received'
        except Exception as error:
            result.server = f'{type(error).__name__}: {error}'
            ready.set()
        finally:
            listener.close()
            server_finished.set()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    ready.wait(timeout=5)
    if result.server and not thread.is_alive():
        result.client = 'Not attempted: server configuration failed'
        return result
    try:
        context = client_context(pki, config)
        with socket.create_connection(('127.0.0.1', port), timeout=4) as raw:
            raw.settimeout(4)
            with context.wrap_socket(raw, server_hostname=config.hostname) as tls:
                result.tls_version = tls.version() or ''
                result.cipher = str(tls.cipher())
                result.client_peer = str(tls.getpeercert().get('subject', 'none')) if tls.getpeercert() else 'unverified'
                tls.sendall(b'GET /hello HTTP/1.0\r\n\r\n')
                chunks = []
                while True:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                result.response = b''.join(chunks).decode('utf-8', errors='replace')
                result.client = 'Handshake accepted; HTTP response received'
    except Exception as error:
        result.client = f'{type(error).__name__}: {error}'
    server_finished.wait(timeout=5)
    thread.join(timeout=1)
    return result
