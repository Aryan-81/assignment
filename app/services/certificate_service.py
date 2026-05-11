from sqlalchemy.orm import Session
from sqlalchemy import or_
from app.models.certificate import Host, Certificate, CertificateSAN, TLSDetail, CertificateChain, SecurityCheck
from app.services.cert_utils import get_cert_info, parse_host
from datetime import datetime

def get_or_create_certificate(db: Session, url: str):
    hostname = parse_host(url)
    port = 443  # Default

    # 1. Check if host exists
    host = db.query(Host).filter(Host.hostname == hostname, Host.port == port).first()
    
    # if not host:
    #     # 2. Check if hostname exists in SANs
    #     san_entry = db.query(CertificateSAN).filter(CertificateSAN.san_value == hostname).first()
    #     if san_entry:
    #         # If found in SAN, get the associated certificate's host
    #         return san_entry.certificate.host

    if host and host.certificates:
        # For simplicity, return the most recent certificate
        # In a real app, you might check if it's expired
        return host

    # 3. Fetch fresh data if not found
    cert_data = get_cert_info(hostname, port)
    
    # 4. Save to database
    # Create Host
    print("\n\nScanning Network for host: ", hostname, "\n\n")
    new_host = Host(hostname=hostname, port=port)
    db.add(new_host)
    db.flush() # Get host.id

    cert_info = cert_data["certificate"]
    validity = cert_info["validity"]
    
    # Create Certificate
    db_cert = Certificate(
        host_id=new_host.id,
        serial_number=cert_info["serial_number"],
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
        db_san = CertificateSAN(certificate_id=db_cert.id, san_value=san_val)
        db.add(db_san)

    # Create TLS Details
    tls_info = cert_data["tls"]
    db_tls = TLSDetail(
        certificate_id=db_cert.id,
        tls_version=tls_info["version"],
        cipher_suite=tls_info["cipher_suite"],
        cipher_protocol=tls_info["cipher_protocol"],
        secret_bits=tls_info["secret_bits"]
    )
    db.add(db_tls)

    # Create Certificate Chain
    # Note: chain_info["certificate_chain"] is the list
    chain_list = cert_data["certificate_chain"]["certificate_chain"]
    for entry in chain_list:
        db_chain = CertificateChain(
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
        )
        db.add(db_chain)

    # Create Security Checks
    sec_info = cert_data["security_checks"]
    db_sec = SecurityCheck(
        certificate_id=db_cert.id,
        is_expired=sec_info["is_expired"],
        expires_soon=sec_info["expires_soon"],
        strong_tls=sec_info["strong_tls"]
    )
    db.add(db_sec)

    db.commit()
    db.refresh(new_host)
    
    return new_host
