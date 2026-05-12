from sqlalchemy.orm import Session
from app.models import Host, Certificate, CertificateScan
from sqlalchemy import desc
from typing import List


class QueryRepository:
    @staticmethod
    def get_host(db: Session, hostname: str, port: int=443):
        """Fetch a host record by hostname and port."""
        return db.query(Host).filter(Host.hostname == hostname, Host.port == port).first()

    @staticmethod
    def get_certificate_by_serial(db: Session, serial: str):
        """Fetch a certificate record by its serial number."""
        return db.query(Certificate).filter(Certificate.serial_number == serial).first()

    @staticmethod
    def get_latest_scan_result(db: Session, host_id: int):
        """Retrieve the most recent certificate from a host's scan history."""
        scan = db.query(CertificateScan).filter(CertificateScan.host_id == host_id)\
                 .order_by(CertificateScan.scanned_at.desc()).first()
        return scan.certificate if scan else None

    @staticmethod
    def get_latest_scans_for_hosts(db: Session, host_ids: List[int]) -> List[CertificateScan]:
        """Get the latest scan entry for multiple host IDs efficiently."""
        from sqlalchemy import func
        # Subquery to get the latest scanned_at for each host
        subquery = (
            db.query(
                CertificateScan.host_id,
                func.max(CertificateScan.scanned_at).label("latest_scanned_at")
            )
            .filter(CertificateScan.host_id.in_(host_ids))
            .group_by(CertificateScan.host_id)
            .subquery()
        )

        # Join to get the full scan objects for those latest times
        return (
            db.query(CertificateScan)
            .join(
                subquery,
                (CertificateScan.host_id == subquery.c.host_id) &
                (CertificateScan.scanned_at == subquery.c.latest_scanned_at)
            )
            .all()
        )
    @staticmethod
    def get_scan_by_host_and_certificate(
        db: Session,
        host_id: int,
        certificate_id: int,
    ):
        """Find a specific scan record for a given host and certificate."""
        return (
            db.query(CertificateScan)
            .filter(
                CertificateScan.host_id == host_id,
                CertificateScan.certificate_id == certificate_id,
            )
            .first()
        )
    @staticmethod
    def get_paginated_hosts(db: Session, offset: int, limit: int) -> List[Host]:
        """Fetch a list of hosts with pagination and reverse chronological order."""
        return (
            db.query(Host)
            .order_by(desc(Host.created_at))
            .offset(offset)
            .limit(limit)
            .all()
        )