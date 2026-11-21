"""Each scenario changes exactly one independent TLS configuration dimension."""
from __future__ import annotations
import ssl
from dataclasses import dataclass, replace
from .transport import Configuration


@dataclass(frozen=True)
class Scenario:
    name: str
    explanation: str
    config: Configuration
    expected_success: bool


BASE = Configuration()
SCENARIOS = {
    s.name: s for s in [
        Scenario('success', 'Both peers trust the issuer, certificates have correct EKUs, and hostname matches.', BASE, True),
        Scenario('missing-client-cert', 'Client presents no certificate; server requires one.', replace(BASE, client_cert=None), False),
        Scenario('untrusted-client', 'Client certificate is signed by a CA the server does not trust.', replace(BASE, client_cert='rogue-client'), False),
        Scenario('expired-client', 'Client certificate notAfter is in 2020.', replace(BASE, client_cert='expired-client'), False),
        Scenario('wrong-client-eku', 'Client certificate is validly signed but only has serverAuth EKU.', replace(BASE, client_cert='wrong-eku-client'), False),
        Scenario('untrusted-server', 'Server certificate is signed by a CA the client does not trust.', replace(BASE, server_cert='rogue-server'), False),
        Scenario('hostname-mismatch', 'Server certificate is valid but SAN does not match localhost.', replace(BASE, server_cert='wrong-host-server'), False),
        Scenario('wrong-server-eku', 'Server certificate has clientAuth instead of serverAuth.', replace(BASE, server_cert='wrong-eku-server'), False),
        Scenario('wrong-client-trust-store', 'Client trusts the rogue CA rather than the issuing server CA.', replace(BASE, client_trust='rogue-ca'), False),
        Scenario('wrong-server-trust-store', 'Server trusts the rogue CA rather than the issuing client CA.', replace(BASE, server_trust='rogue-ca'), False),
        Scenario('tls-version-mismatch', 'Server requires TLS 1.3; client only offers TLS 1.2.', replace(BASE, server_minimum=ssl.TLSVersion.TLSv1_3, client_maximum=ssl.TLSVersion.TLSv1_2), False),
        Scenario('client-auth-disabled', 'Deliberate insecure control: TLS succeeds without client authentication.', replace(BASE, client_cert=None, server_requires_client_cert=False), True),
        Scenario('server-verification-disabled', 'Deliberate insecure control: client accepts an untrusted server.', replace(BASE, server_cert='rogue-server', client_verifies_server=False), True),
    ]
}
