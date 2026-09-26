"""
Local certificate authority for the social media block page.

Generates a root CA once, installs it into Windows' trusted root store, and
issues a leaf certificate (signed by that CA) for each blocked domain --
this is what lets block_page_server.py present a certificate the browser
actually trusts when it's redirected to our local "Access Restricted" page
over HTTPS, instead of a certificate-error page.

Everything is generated once and cached on disk under certs/ next to this
file; subsequent runs reuse the same CA and certs rather than regenerating
them (regenerating would mean reinstalling the root CA into Windows' trust
store every time, which is unnecessary and slow).
"""
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CERT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
CA_KEY_PATH = os.path.join(CERT_DIR, "ueba_root_ca.key")
CA_CERT_PATH = os.path.join(CERT_DIR, "ueba_root_ca.crt")
CA_INSTALLED_MARKER = os.path.join(CERT_DIR, ".ca_installed")


def _load_or_generate_root_ca():
    os.makedirs(CERT_DIR, exist_ok=True)

    if os.path.exists(CA_KEY_PATH) and os.path.exists(CA_CERT_PATH):
        with open(CA_KEY_PATH, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        with open(CA_CERT_PATH, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        return key, cert

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "UEBA Local Block CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UEBA System"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .sign(key, hashes.SHA256())
    )

    with open(CA_KEY_PATH, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with open(CA_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return key, cert


def ensure_root_ca_installed() -> None:
    """Installs the root CA into Windows' Trusted Root Certification
    Authorities store, once. This is what makes the browser trust our
    generated leaf certificates instead of showing a certificate warning.
    Safe to call on every startup -- it's a no-op after the first
    successful install (tracked by CA_INSTALLED_MARKER)."""
    _load_or_generate_root_ca()  # ensures the cert file exists on disk

    if os.path.exists(CA_INSTALLED_MARKER):
        return

    try:
        result = subprocess.run(
            ["certutil", "-addstore", "Root", CA_CERT_PATH],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            with open(CA_INSTALLED_MARKER, "w") as f:
                f.write(datetime.now(timezone.utc).isoformat())
            print("Root CA installed into Windows' trusted root store.")
        else:
            print(
                f"Could not install root CA (certutil exit code {result.returncode}): "
                f"{result.stderr.strip()}. The block page will show a certificate warning "
                f"until this is resolved -- try running this script elevated.",
                file=sys.stderr,
            )
    except (subprocess.SubprocessError, OSError, FileNotFoundError) as e:
        print(f"Could not run certutil to install the root CA: {e}", file=sys.stderr)


def get_leaf_cert_paths(domain: str) -> str:
    """Returns the path to a combined cert+key PEM file for this domain,
    generating and caching it on first request. One file per domain also
    covers its www. subdomain via SAN."""
    combined_path = os.path.join(CERT_DIR, f"{domain}.pem")
    if os.path.exists(combined_path):
        return combined_path

    ca_key, ca_cert = _load_or_generate_root_ca()

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=825))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain), x509.DNSName(f"www.{domain}")]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    with open(combined_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        f.write(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    return combined_path


def ensure_leaf_certs(domains) -> dict:
    """Pre-generates leaf certs for every domain up front (rather than
    generating on first connection), so the server has everything ready
    before it starts accepting connections. Returns {domain: pem_path}."""
    return {domain: get_leaf_cert_paths(domain) for domain in domains}
