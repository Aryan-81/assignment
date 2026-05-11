import socket
import ssl
import json
from OpenSSL import SSL
from datetime import datetime, timezone
from urllib.parse import urlparse


def parse_host(url_or_domain: str):
    """
    Extract hostname from URL or raw domain.
    """
    if "://" not in url_or_domain:
        url_or_domain = "https://" + url_or_domain

    parsed = urlparse(url_or_domain)
    return parsed.hostname

def cert_name_to_dict(name):
    result = {}

    for k, v in name.get_components():
        result[k.decode()] = v.decode()

    return result

def get_cert_chain(hostname, port=443):

    ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((hostname, port))

    conn = SSL.Connection(ctx, sock)
    conn.set_tlsext_host_name(hostname.encode())
    conn.set_connect_state()
    conn.do_handshake()

    chain = conn.get_peer_cert_chain()

    tls_version = conn.get_protocol_version_name()
    cipher = conn.get_cipher_name()

    certs = []

    now = datetime.now(timezone.utc)

    for index, cert in enumerate(chain):

        crypto_cert = cert.to_cryptography()

        subject = cert_name_to_dict(cert.get_subject())
        issuer = cert_name_to_dict(cert.get_issuer())

        not_before = crypto_cert.not_valid_before_utc
        not_after = crypto_cert.not_valid_after_utc

        cert_data = {
            "position": index,
            "subject": {
                "common_name": subject.get("CN"),
                "organization": subject.get("O"),
                "country": subject.get("C"),
            },
            "issuer": {
                "common_name": issuer.get("CN"),
                "organization": issuer.get("O"),
                "country": issuer.get("C"),
            },
            "serial_number": str(cert.get_serial_number()),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_left": (not_after - now).days,
        }

        certs.append(cert_data)

    result = {
        "host": hostname,
        "tls": {
            "version": tls_version,
            "cipher_suite": cipher,
        },
        "certificate_chain": certs,
    }

    conn.close()
    sock.close()

    return result


def get_cert_info(hostname: str, port: int = 443):
    """
    Connect to server using TLS and fetch certificate + TLS details.
    """

    context = ssl.create_default_context()

    # Enable hostname verification
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    result = {}

    with socket.create_connection((hostname, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:

            # Peer certificate
            cert = ssock.getpeercert()

            # TLS details
            tls_version = ssock.version()
            cipher = ssock.cipher()

            # Certificate validity
            not_before = cert.get("notBefore")
            not_after = cert.get("notAfter")

            dt_format = "%b %d %H:%M:%S %Y %Z"

            issued_date = datetime.strptime(not_before, dt_format).replace(
                tzinfo=timezone.utc
            )
            expiry_date = datetime.strptime(not_after, dt_format).replace(
                tzinfo=timezone.utc
            )

            now = datetime.now(timezone.utc)

            days_left = (expiry_date - now).days

            # Subject details
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))

            # SANs
            san = cert.get("subjectAltName", [])

            # CA chain (best effort)
            chain_info = get_cert_chain(hostname,port)

            

            result = {
                "host": hostname,
                "port": port,

                "certificate": {
                    "subject": {
                        "common_name": subject.get("commonName"),
                        "organization": subject.get("organizationName"),
                        "country": subject.get("countryName"),
                    },

                    "issuer": {
                        "common_name": issuer.get("commonName"),
                        "organization": issuer.get("organizationName"),
                        "country": issuer.get("countryName"),
                    },

                    "serial_number": cert.get("serialNumber"),

                    "validity": {
                        "not_before": issued_date.isoformat(),
                        "not_after": expiry_date.isoformat(),
                        "days_left": days_left,
                    },

                    "subject_alt_names": [
                        value for key, value in san if key == "DNS"
                    ],
                },

                "tls": {
                    "version": tls_version,
                    "cipher_suite": cipher[0] if cipher else None,
                    "cipher_protocol": cipher[1] if cipher else None,
                    "secret_bits": cipher[2] if cipher else None,
                },

                "certificate_chain": chain_info,

                "security_checks": {
                    "is_expired": days_left < 0,
                    "expires_soon": days_left <= 30,
                    "strong_tls": tls_version in ["TLSv1.2", "TLSv1.3"],
                },
            }

    return result


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