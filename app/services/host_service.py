from sqlalchemy.orm import Session
from app.query_repo import QueryRepository as repo
from app.utils.helper import cleanup_orphan_certificates
from app.schema.certificate import HostWithCertificatesResponse
from app.services.certificate_service import get_or_create_certificate

def get_paginated_hosts_with_latest_scan(db: Session, page: int, page_size: int):
    offset = (page - 1) * page_size
    
    # 1. Fetch data via Repo
    hosts = repo.get_paginated_hosts(db, offset, page_size)
    if not hosts:
        return []

    host_ids = [host.id for host in hosts]
    latest_scans = repo.get_latest_scan_result(db, host_ids)

    # 2. Map results
    certificate_map = {scan.host_id: scan.certificate for scan in latest_scans}

    return [
        HostWithCertificatesResponse(
            success=True,
            host=host,
            certificate=certificate_map.get(host.id)
        ) for host in hosts
    ]

def delete_host_and_orphans(db: Session, hostname: str) -> bool:
    host = repo.get_host(db, hostname)
    if not host:
        return False

    # Logic: Keep track of IDs before deletion
    certificate_ids = [s.certificate_id for s in host.scans if s.certificate_id]
    
    db.delete(host)
    db.commit()

    if certificate_ids:
        cleanup_orphan_certificates(db, certificate_ids)
    return True

def get_host_or_create(db: Session, hostname: str):
    host = repo.get_host(db, hostname)

    if not host:
        # Business logic: trigger a new scan if host doesn't exist
        data = get_or_create_certificate(db, hostname)
        if data["success"]:
            host = data["host"]
        else:
            # Handle or log error
            return None
    return host