from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.models import (
    Host,
    CertificateScan,
)

from app.utils.cert_utils import get_cert_info, map_cert_data_to_models
from app.utils.helper import is_cache_valid, parse_host
from app.query_repo import QueryRepository as Repo


def get_or_create_certificate(db: Session, url: str, port: int = 443):
    hostname = parse_host(url)
    if not hostname:
        return {"success": False, "error": "Invalid hostname"}

    # 1. Check Cache
    host = Repo.get_host(db, hostname, port)
    if host and host.last_scan_status == "success" and is_cache_valid(host.last_scan_at):
        return {
            "success": True, 
            "cached": True, 
            "host": host, 
            "certificate": Repo.get_latest_scan_result(db, host.id)
        }

    # 2. Ensure Host exists
    if not host:
        host = Host(hostname=hostname, port=port)
        db.add(host)
        db.flush()

    # 3. Perform Network Scan
    try:
        cert_data = get_cert_info(hostname, port)
    except Exception as e:
        host.last_scan_status = "failed"
        db.commit()
        return {"success": False, "error": str(e), "host": host}

    # 4. Process Certificate
    serial_no = cert_data["certificate"]["serial_number"]
    db_cert = Repo.get_certificate_by_serial(db, serial_no)

    if not db_cert:
        db_cert = map_cert_data_to_models(cert_data)
        db.add(db_cert)
        db.flush()

    # 5. Finalize Scan Entry
    host.last_scan_at = datetime.now(timezone.utc)
    host.last_scan_status = "success"
    
    scan_entry = CertificateScan(host_id=host.id, certificate_id=db_cert.id, raw_json=cert_data)
    db.add(scan_entry)
    
    db.commit()
    db.refresh(host)

    return {"success": True, "cached": False, "host": host, "certificate": db_cert}

def get_certificate_no_cache(db: Session, url: str, port: int = 443):
    hostname = parse_host(url)
    if not hostname:
        return {"success": False, "error": "Invalid hostname"}

    # 2. Ensure Host exists
    host = Repo.get_host(db, hostname, port)
    if not host:
        host = Host(hostname=hostname, port=port)
        db.add(host)
        db.flush()

    # 3. Perform Network Scan
    try:
        cert_data = get_cert_info(hostname, port)
    except Exception as e:
        host.last_scan_status = "failed"
        db.commit()
        return {"success": False, "error": str(e), "host": host}

    # 4. Process Certificate
    serial_no = cert_data["certificate"]["serial_number"]
    db_cert = Repo.get_certificate_by_serial(db, serial_no)

    if not db_cert:
        db_cert = map_cert_data_to_models(cert_data)
        db.add(db_cert)
        db.flush()

    # 5. Finalize Scan Entry
    host.last_scan_at = datetime.now(timezone.utc)
    host.last_scan_status = "success"
    
    existing_scan = Repo.get_scan_by_host_and_certificate(
        db,
        host.id,
        db_cert.id,
    )

    if existing_scan:

        existing_scan.raw_json = cert_data
        existing_scan.scanned_at = datetime.now(
            timezone.utc
        )

    else:

        scan_entry = CertificateScan(
            host_id=host.id,
            certificate_id=db_cert.id,
            raw_json=cert_data,
        )

        db.add(scan_entry)
    
    db.commit()
    db.refresh(host)

    return {"success": True, "cached": False, "host": host, "certificate": db_cert}
