"""Local development only: create a disposable CA and two independent identities."""
import argparse
import datetime as dt
import hashlib
import ipaddress
import json
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def generate(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Cripto Agent Development CA')])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(days=7))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    (directory / 'ca.crt').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    fingerprints = {}
    for agent in ['agent-a', 'agent-b']:
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent)]))
                .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(days=7))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, None, None), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                .sign(ca_key, hashes.SHA256()))
        (directory / f'{agent}.crt').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        with (directory / f'{agent}.key').open('xb') as stream:
            stream.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        fingerprints[agent] = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    for agent, port in [('agent-a', 8443), ('agent-b', 8444)]:
        other = 'agent-b' if agent == 'agent-a' else 'agent-a'
        config = dict(organization='demo-org', agent_id=agent, ca='ca.crt', cert=f'{agent}.crt',
                      key=f'{agent}.key', database=f'{agent}.sqlite3', bind='127.0.0.1', port=port,
                      peers={fingerprints[other]: other}, permissions=[[other, 'tool', 'echo'], [other, 'skill', 'text.stats']],
                      directory={'agent-a': 'https://localhost:8443', 'agent-b': 'https://localhost:8444'})
        (directory / f'{agent}.json').write_text(json.dumps(config, indent=2), encoding='utf-8')
    # CA signing key is intentionally not persisted.


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', default='.local/pki')
    generate(parser.parse_args().out)
