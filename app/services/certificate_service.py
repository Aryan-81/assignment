from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    Host,
    CertificateScan,
)

from app.utils.cert_utils import get_cert_info, map_cert_data_to_models
from app.utils.helper import is_cache_valid, parse_host
from app.utils.error_handler import handle_scan_error, format_success_response, ScanException
from app.query_repo import QueryRepository as Repo


async def get_or_create_certificate(db: AsyncSession, url: str, port: int = 443):
    """Retrieve certificate from cache if valid, otherwise perform a network scan."""
    hostname = parse_host(url)
    if not hostname:
        raise ScanException("Invalid hostname")

    # Check Cache
    host = await Repo.get_host(db, hostname, port)
    if host and host.last_scan_status == "success" and is_cache_valid(host.last_scan_at):
        return format_success_response(
            host=host, 
            certificate=await Repo.get_latest_scan_result(db, host.id), 
            cached=True
        )

    # Ensure Host exists
    if not host:
        host = Host(hostname=hostname, port=port)
        db.add(host)
        await db.flush()

    # Perform Network Scan
    try:
        cert_data = await get_cert_info(hostname, port)
    except Exception as e:
        # Remove host from DB on failure as requested
        await db.delete(host)
        await db.commit()
        handle_scan_error(e, raise_exc=True)

    # Process Certificate
    serial_no = cert_data["certificate"]["serial_number"]
    db_cert = await Repo.get_certificate_by_serial(db, serial_no)

    if not db_cert:
        db_cert = map_cert_data_to_models(cert_data)
        db.add(db_cert)
    else:
        # Update existing certificate with missing details (like chain entries)
        db_cert = map_cert_data_to_models(cert_data, cert=db_cert)
    
    await db.flush()

    # Finalize Scan Entry
    host.last_scan_at = datetime.now(timezone.utc)
    host.last_scan_status = "success"
    
    scan_entry = CertificateScan(host_id=host.id, certificate_id=db_cert.id, raw_json=cert_data)
    db.add(scan_entry)
    
    await db.commit()
    await db.refresh(host)

    return format_success_response(host=host, certificate=db_cert, cached=False)

async def get_certificate_no_cache(db: AsyncSession, url: str, port: int = 443):
    """Bypass cache and perform a fresh network scan for the certificate."""
    hostname = parse_host(url)
    if not hostname:
        raise ScanException("Invalid hostname")

    # Ensure Host exists
    host = await Repo.get_host(db, hostname, port)
    if not host:
        host = Host(hostname=hostname, port=port)
        db.add(host)
        await db.flush()

    # Perform Network Scan
    try:
        cert_data = await get_cert_info(hostname, port)
    except Exception as e:
        # Remove host from DB on failure as requested
        await db.delete(host)
        await db.commit()
        handle_scan_error(e, raise_exc=True)

    # Process Certificate
    serial_no = cert_data["certificate"]["serial_number"]
    db_cert = await Repo.get_certificate_by_serial(db, serial_no)

    if not db_cert:
        db_cert = map_cert_data_to_models(cert_data)
        db.add(db_cert)
    else:
        # Update existing certificate with missing details (like chain entries)
        db_cert = map_cert_data_to_models(cert_data, cert=db_cert)
    
    await db.flush()

    # Finalize Scan Entry
    host.last_scan_at = datetime.now(timezone.utc)
    host.last_scan_status = "success"
    
    existing_scan = await Repo.get_scan_by_host_and_certificate(
        db,
        host.id,
        db_cert.id,
    )

    if existing_scan:
        existing_scan.raw_json = cert_data
        existing_scan.scanned_at = datetime.now(timezone.utc)
    else:
        scan_entry = CertificateScan(
            host_id=host.id,
            certificate_id=db_cert.id,
            raw_json=cert_data,
        )
        db.add(scan_entry)
    
    await db.commit()
    await db.refresh(host)

    return format_success_response(host=host, certificate=db_cert, cached=False)
