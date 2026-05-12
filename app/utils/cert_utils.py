import socket
import ssl
import json
from OpenSSL import SSL
from datetime import datetime, timezone
from app.utils.helper import parse_host
from app.models import (
    Certificate,
    CertificateSAN,
    TLSDetail,
    CertificateChain,
    SecurityCheck,
)
from cryptography import x509

def cert_name_to_dict(name):
    """
    Convert X509 name components to dict.
    """
    result = {}

    for k, v in name.get_components():
        result[k.decode()] = v.decode()

    return result

def get_cert_info(hostname: str, port: int = 443):

    # ── Build a context that can actually complete the handshake ──────────
    ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
    ctx.set_default_verify_paths()                      # load system CA bundle
    ctx.set_verify(SSL.VERIFY_PEER, lambda conn, cert, errnum, depth, ok: ok)

    # Blocking socket with a timeout so do_handshake() doesn't hang
    sock = socket.create_connection((hostname, port), timeout=10)
    sock.setblocking(True)

    conn = SSL.Connection(ctx, sock)
    conn.set_tlsext_host_name(hostname.encode())        # SNI
    conn.set_connect_state()

    # Drive the handshake; retry on WANT_READ (non-fatal on some platforms)
    while True:
        try:
            conn.do_handshake()
            break
        except SSL.WantReadError:
            pass

    # ── Collect everything before closing ─────────────────────────────────
    chain        = conn.get_peer_cert_chain()
    tls_version  = conn.get_protocol_version_name()
    cipher_name  = conn.get_cipher_name()
    cipher_proto = conn.get_cipher_version()
    cipher_bits  = conn.get_cipher_bits()

    conn.close()
    sock.close()

    now = datetime.now(timezone.utc)

    # ── Leaf certificate ───────────────────────────────────────────────────
    leaf        = chain[0]
    crypto_leaf = leaf.to_cryptography()
    subject     = cert_name_to_dict(leaf.get_subject())
    issuer      = cert_name_to_dict(leaf.get_issuer())

    not_before = crypto_leaf.not_valid_before_utc
    not_after  = crypto_leaf.not_valid_after_utc
    days_left  = (not_after - now).days

    san_list = []
    try:
        san_ext  = crypto_leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_list = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    #  Full chain (root-first) 
    certs = []
    for index, cert in enumerate(reversed(chain)):
        crypto_cert = cert.to_cryptography()
        s  = cert_name_to_dict(cert.get_subject())
        i  = cert_name_to_dict(cert.get_issuer())
        nb = crypto_cert.not_valid_before_utc
        na = crypto_cert.not_valid_after_utc

        certs.append({
            "position":      index,
            "subject":       {"common_name": s.get("CN"), "organization": s.get("O"), "country": s.get("C")},
            "issuer":        {"common_name": i.get("CN"), "organization": i.get("O"), "country": i.get("C")},
            "serial_number": format(cert.get_serial_number(), "X"),
            "not_before":    nb.isoformat(),
            "not_after":     na.isoformat(),
            "days_left":     (na - now).days,
        })

    result = {
        "host": hostname,
        "port": port,

        "certificate": {
            "subject":       {"common_name": subject.get("CN"), "organization": subject.get("O"), "country": subject.get("C")},
            "issuer":        {"common_name": issuer.get("CN"),  "organization": issuer.get("O"),  "country": issuer.get("C")},
            "serial_number": format(leaf.get_serial_number(), "X"),
            "validity": {
                "not_before": not_before.isoformat(),
                "not_after":  not_after.isoformat(),
                "days_left":  days_left,
            },
            "subject_alt_names": san_list,
        },

        "tls": {
            "version":         tls_version,
            "cipher_suite":    cipher_name,
            "cipher_protocol": cipher_proto,
            "secret_bits":     cipher_bits,
        },

        "certificate_chain": certs,

        "security_checks": {
            "is_expired":   days_left < 0,
            "expires_soon": days_left <= 30,
            "strong_tls":   tls_version in ["TLSv1.2", "TLSv1.3"],
        },
    }

    return(result)

def map_cert_data_to_models(cert_data: dict, cert: Certificate = None) -> Certificate:
    """Converts raw cert_data dictionary into a full ORM object graph."""
    info = cert_data["certificate"]
    
    # 1. Base Certificate
    if cert is None:
        cert = Certificate(
            serial_number=info["serial_number"],
            subject_common_name=info["subject"].get("common_name"),
            subject_organization=info["subject"].get("organization"),
            subject_country=info["subject"].get("country"),
            issuer_common_name=info["issuer"].get("common_name"),
            issuer_organization=info["issuer"].get("organization"),
            issuer_country=info["issuer"].get("country"),
            not_before=datetime.fromisoformat(info["validity"]["not_before"]),
            not_after=datetime.fromisoformat(info["validity"]["not_after"]),
            days_left=info["validity"].get("days_left"),
        )
    else:
        # Update fields if they might have changed or were missing
        cert.days_left = info["validity"].get("days_left")
        cert.not_after = datetime.fromisoformat(info["validity"]["not_after"])
    
    # 2. SANs (Only add if missing to avoid duplicates)
    if not cert.sans:
        cert.sans = [CertificateSAN(san_value=val) for val in info["subject_alt_names"]]
    
    # 3. TLS Details (Always update/create)
    tls_data = cert_data.get("tls", {})
    if not cert.tls_detail:
        cert.tls_detail = TLSDetail(
            tls_version=tls_data.get("version"),
            cipher_suite=tls_data.get("cipher_suite"),
            cipher_protocol=tls_data.get("cipher_protocol"),
            secret_bits=tls_data.get("secret_bits"),
        )
    else:
        cert.tls_detail.tls_version = tls_data.get("version")
        cert.tls_detail.cipher_suite = tls_data.get("cipher_suite")
        cert.tls_detail.cipher_protocol = tls_data.get("cipher_protocol")
        cert.tls_detail.secret_bits = tls_data.get("secret_bits")

    # 4. Chain 
    if not cert.chain_entries:
        for i, entry in enumerate(cert_data.get("certificate_chain", [])):
            cert.chain_entries.append(CertificateChain(
                chain_position=entry.get("position", i),
                serial_number=entry.get("serial_number"),
                subject_common_name=entry.get("subject", {}).get("common_name"),
                subject_organization=entry.get("subject", {}).get("organization"),
                subject_country=entry.get("subject", {}).get("country"),
                issuer_common_name=entry.get("issuer", {}).get("common_name"),
                issuer_organization=entry.get("issuer", {}).get("organization"),
                issuer_country=entry.get("issuer", {}).get("country"),
                not_before=datetime.fromisoformat(entry["not_before"]),
                not_after=datetime.fromisoformat(entry["not_after"]),
                days_left=entry.get("days_left"),
            ))

    # 5. Security Checks
    sec = cert_data.get("security_checks", {})
    if not cert.security_check:
        cert.security_check = SecurityCheck(
            is_expired=sec.get("is_expired", False),
            expires_soon=sec.get("expires_soon", False),
            strong_tls=sec.get("strong_tls", False),
            checked_at=datetime.now(timezone.utc)
        )
    else:
        cert.security_check.is_expired = sec.get("is_expired", False)
        cert.security_check.expires_soon = sec.get("expires_soon", False)
        cert.security_check.strong_tls = sec.get("strong_tls", False)
        cert.security_check.checked_at = datetime.now(timezone.utc)
    
    return cert


if __name__ == "__main__":

    website = input("Enter website URL/domain: ").strip()

    try:
        hostname = parse_host(website)

        data = get_cert_info(hostname)

        print(json.dumps(data, indent=4))

    except ssl.SSLError as e:
        print(json.dumps({
            "error": "SSL Error",
            "details": str(e)
        }, indent=4))

    except socket.gaierror:
        print(json.dumps({
            "error": "DNS resolution failed"
        }, indent=4))

    except Exception as e:
        print(json.dumps({
            "error": "Unexpected error",
            "details": str(e)
        }, indent=4))