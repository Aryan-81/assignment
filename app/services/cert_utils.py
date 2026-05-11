import socket
import ssl
import json
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
            chain_info = []

            if hasattr(ssock, "get_verified_chain"):
                try:
                    chain = ssock.get_verified_chain()

                    for idx, cert_obj in enumerate(chain):
                        try:
                            subject_data = cert_obj.get_subject()
                            issuer_data = cert_obj.get_issuer()

                            chain_info.append({
                                "position": idx,
                                "subject_common_name": getattr(
                                    subject_data, "CN", None
                                ),
                                "subject_organization": getattr(
                                    subject_data, "O", None
                                ),
                                "issuer_common_name": getattr(
                                    issuer_data, "CN", None
                                ),
                                "issuer_organization": getattr(
                                    issuer_data, "O", None
                                ),
                            })
                        except Exception as e:
                            chain_info.append({
                                "position": idx,
                                "error": str(e)
                            })

                except Exception:
                    pass

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