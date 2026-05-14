from sqlalchemy.ext.asyncio import AsyncSession
from app.models import Host, Certificate, CertificateScan
from sqlalchemy import desc, select, func
from sqlalchemy.orm import selectinload
from typing import List


class QueryRepository:
    @staticmethod
    async def get_host(db: AsyncSession, hostname: str, port: int = 443):
        """Fetch a host record by hostname and port with relationships loaded."""
        stmt = (
            select(Host)
            .filter(Host.hostname == hostname, Host.port == port)
            .options(selectinload(Host.certificates), selectinload(Host.scans))
        )
        result = await db.execute(stmt)
        return result.scalars().first()

    @staticmethod
    async def get_certificate_by_serial(db: AsyncSession, serial: str):
        """Fetch a certificate record by its serial number."""
        stmt = select(Certificate).filter(Certificate.serial_number == serial)
        result = await db.execute(stmt)
        return result.scalars().first()

    @staticmethod
    async def get_latest_scan_result(db: AsyncSession, host_id: int):
        """Retrieve the most recent certificate from a host's scan history."""
        stmt = (
            select(CertificateScan)
            .filter(CertificateScan.host_id == host_id)
            .order_by(CertificateScan.scanned_at.desc())
            .options(
                selectinload(CertificateScan.certificate).selectinload(Certificate.sans),
                selectinload(CertificateScan.certificate).selectinload(Certificate.tls_detail),
                selectinload(CertificateScan.certificate).selectinload(Certificate.security_check),
                selectinload(CertificateScan.certificate).selectinload(Certificate.chain_entries),
            )
        )
        result = await db.execute(stmt)
        scan = result.scalars().first()
        return scan.certificate if scan else None

    @staticmethod
    async def get_latest_scans_for_hosts(db: AsyncSession, host_ids: List[int]) -> List[CertificateScan]:
        """Get the latest scan entry for multiple host IDs efficiently."""
        # Subquery to get the latest scanned_at for each host
        subquery = (
            select(
                CertificateScan.host_id,
                func.max(CertificateScan.scanned_at).label("latest_scanned_at")
            )
            .filter(CertificateScan.host_id.in_(host_ids))
            .group_by(CertificateScan.host_id)
            .subquery()
        )

        # Join to get the full scan objects for those latest times
        stmt = (
            select(CertificateScan)
            .join(
                subquery,
                (CertificateScan.host_id == subquery.c.host_id) &
                (CertificateScan.scanned_at == subquery.c.latest_scanned_at)
            )
            .options(
                selectinload(CertificateScan.certificate).selectinload(Certificate.sans),
                selectinload(CertificateScan.certificate).selectinload(Certificate.tls_detail),
                selectinload(CertificateScan.certificate).selectinload(Certificate.security_check),
                selectinload(CertificateScan.certificate).selectinload(Certificate.chain_entries),
            )
        )
        result = await db.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    async def get_scan_by_host_and_certificate(
        db: AsyncSession,
        host_id: int,
        certificate_id: int,
    ):
        """Find a specific scan record for a given host and certificate."""
        stmt = (
            select(CertificateScan)
            .filter(
                CertificateScan.host_id == host_id,
                CertificateScan.certificate_id == certificate_id,
            )
        )
        result = await db.execute(stmt)
        return result.scalars().first()

    @staticmethod
    async def get_paginated_hosts(db: AsyncSession, offset: int, limit: int) -> List[Host]:
        """Fetch a list of hosts with pagination and reverse chronological order."""
        stmt = (
            select(Host)
            .order_by(desc(Host.created_at))
            .offset(offset)
            .limit(limit)
        )
        result = await db.execute(stmt)
        return list(result.scalars().all())