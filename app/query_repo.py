from sqlalchemy.orm import Session
from app.models import Host, Certificate, CertificateScan
from sqlalchemy import desc
from typing import List


class QueryRepository:
    @staticmethod
    def get_host(db: Session, hostname: str, port: int=443):
        return db.query(Host).filter(Host.hostname == hostname, Host.port == port).first()

    @staticmethod
    def get_certificate_by_serial(db: Session, serial: str):
        return db.query(Certificate).filter(Certificate.serial_number == serial).first()

    @staticmethod
    def get_latest_scan_result(db: Session, host_id: int):
        scan = db.query(CertificateScan).filter(CertificateScan.host_id == host_id)\
                 .order_by(CertificateScan.scanned_at.desc()).first()
        return scan.certificate if scan else None
    @staticmethod
    def get_scan_by_host_and_certificate(
        db: Session,
        host_id: int,
        certificate_id: int,
    ):
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
        return (
            db.query(Host)
            .order_by(desc(Host.created_at))
            .offset(offset)
            .limit(limit)
            .all()
        )