from sqlalchemy.orm import Session
from sqlalchemy import or_
from app.models import Host, Certificate, CertificateSAN, TLSDetail, CertificateChain, SecurityCheck, CertificateScan
from app.services.cert_utils import get_cert_info, parse_host
from datetime import datetime


def get_or_create_certificate(db: Session, url: str):
    hostname = parse_host(url)
    port = 443  # Default

    # 1. Check if host exists
    host = db.query(Host).filter(Host.hostname == hostname, Host.port == port).first()
    
    if host and host.certificates:
        # Return existing host if it already has certificates
        return host

    # 2. Fetch fresh data
    print(f"\n\nScanning Network for host: {hostname}\n\n")
    cert_data = get_cert_info(hostname, port)
    cert_info = cert_data["certificate"]
    serial_number = cert_info["serial_number"]

    # 3. Handle Host creation
    if not host:
        host = Host(hostname=hostname, port=port)
        db.add(host)
        db.flush()

    # 4. Check for existing certificate by serial number (Deduplication)
    db_cert = db.query(Certificate).filter(Certificate.serial_number == serial_number).first()
    
    if not db_cert:
        validity = cert_info["validity"]
        # Create new Certificate entry if it doesn't exist
        db_cert = Certificate(
            serial_number=serial_number,
            subject_common_name=cert_info["subject"]["common_name"],
            subject_organization=cert_info["subject"]["organization"],
            subject_country=cert_info["subject"]["country"],
            issuer_common_name=cert_info["issuer"]["common_name"],
            issuer_organization=cert_info["issuer"]["organization"],
            issuer_country=cert_info["issuer"]["country"],
            not_before=datetime.fromisoformat(validity["not_before"]),
            not_after=datetime.fromisoformat(validity["not_after"]),
            days_left=validity["days_left"]
        )
        db.add(db_cert)
        db.flush()

        # Create SANs
        for san_val in cert_info["subject_alt_names"]:
            db.add(CertificateSAN(certificate_id=db_cert.id, san_value=san_val))

        # Create TLS Details
        tls_info = cert_data["tls"]
        db.add(TLSDetail(
            certificate_id=db_cert.id,
            tls_version=tls_info["version"],
            cipher_suite=tls_info["cipher_suite"],
            cipher_protocol=tls_info["cipher_protocol"],
            secret_bits=tls_info["secret_bits"]
        ))

        # Create Certificate Chain
        chain_list = cert_data["certificate_chain"]["certificate_chain"]
        for entry in chain_list:
            db.add(CertificateChain(
                certificate_id=db_cert.id,
                chain_position=entry["position"],
                serial_number=entry["serial_number"],
                subject_common_name=entry["subject"]["common_name"],
                subject_organization=entry["subject"]["organization"],
                subject_country=entry["subject"]["country"],
                issuer_common_name=entry["issuer"]["common_name"],
                issuer_organization=entry["issuer"]["organization"],
                issuer_country=entry["issuer"]["country"],
                not_before=datetime.fromisoformat(entry["not_before"]),
                not_after=datetime.fromisoformat(entry["not_after"]),
                days_left=entry["days_left"]
            ))

        # Create Security Checks
        sec_info = cert_data["security_checks"]
        db.add(SecurityCheck(
            certificate_id=db_cert.id,
            is_expired=sec_info["is_expired"],
            expires_soon=sec_info["expires_soon"],
            strong_tls=sec_info["strong_tls"]
        ))

    # 5. Create a Scan record (linking the host and certificate)
    scan = CertificateScan(
        host_id=host.id,
        certificate_id=db_cert.id,
        raw_json=cert_data
    )
    db.add(scan)

    db.commit()
    db.refresh(host)
    
    return host
