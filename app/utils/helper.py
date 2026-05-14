from datetime import datetime, timezone, timedelta
from app.core.config import CACHE_TTL_HOURS
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, exists

from urllib.parse import urlparse
from app.models import (
    Host,
    Certificate,
    CertificateScan,
)


def is_cache_valid(last_scan_at):
    """
    Check if the cache is valid based on the last scan time.
    """
    if not last_scan_at:
        return False

    now = datetime.now(timezone.utc)
    age = now - last_scan_at
    return age < timedelta(hours=CACHE_TTL_HOURS)


def parse_host(url_or_domain: str):
    """
    Extract hostname from URL or raw domain.
    """
    if "://" not in url_or_domain:
        url_or_domain = "https://" + url_or_domain

    parsed = urlparse(url_or_domain)
    return parsed.hostname





def get_related_objects(
    host: Host,
    attribute: str,
    filter_none: bool = True
) -> list:
    """
    Generic helper to extract related objects from host's certificates.
    
    Args:
        host: Host object with certificates relationship
        attribute: Attribute name to extract from each certificate
        filter_none: If True, filters out None values
    
    Returns:
        List of related objects
    """
    items = []
    
    for cert in host.certificates:
        if hasattr(cert, attribute):
            item = getattr(cert, attribute)
            if not filter_none or item is not None:
                if isinstance(item, list):
                    items.extend(item)
                else:
                    items.append(item)
    
    return items


async def cleanup_orphan_certificates(db: AsyncSession, certificate_ids: list[int]) -> None:
    """
    Delete certificates that are no longer referenced by any scan.
    
    Args:
        db: Database session
        certificate_ids: List of certificate IDs to check
    """
    for cert_id in certificate_ids:
        stmt = select(exists().where(CertificateScan.certificate_id == cert_id))
        result = await db.execute(stmt)
        still_used = result.scalar()

        if not still_used:
            stmt = select(Certificate).filter(Certificate.id == cert_id)
            result = await db.execute(stmt)
            cert = result.scalars().first()

            if cert:
                await db.delete(cert)
    
    await db.commit()
