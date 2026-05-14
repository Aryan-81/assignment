from sqlalchemy.ext.asyncio import AsyncSession
from app.query_repo import QueryRepository as repo
from app.utils.helper import cleanup_orphan_certificates, is_cache_valid
from app.utils.error_handler import format_success_response, ScanException
from app.services.certificate_service import get_or_create_certificate

async def get_paginated_hosts_with_latest_scan(db: AsyncSession, page: int, page_size: int):
    """Retrieve a list of hosts with their latest scan results, triggering rescans if cached data is stale."""
    offset = (page - 1) * page_size
    
    # Fetch data via Repo
    hosts = await repo.get_paginated_hosts(db, offset, page_size)
    if not hosts:
        return []

    host_ids = [host.id for host in hosts]
    latest_scans = await repo.get_latest_scans_for_hosts(db, host_ids)
    certificate_map = {scan.host_id: scan.certificate for scan in latest_scans}

    # Validate cache and rescan if necessary
    results = []
    for host in hosts:
        if not is_cache_valid(host.last_scan_at):
            # Trigger rescan if cache is invalid
            try:
                scan_data = await get_or_create_certificate(db, host.hostname, host.port)
                results.append(scan_data)
                continue
            except ScanException:
                # Fallback to cached data if rescan fails during bulk fetch
                pass
        
        # Use cached data if valid or if rescan failed (fallback)
        results.append(format_success_response(
            host=host,
            certificate=certificate_map.get(host.id),
            cached=True
        ))

    return results

async def delete_host_and_orphans(db: AsyncSession, hostname: str) -> bool:
    """Delete a host and its associated scans, then cleanup any certificates that are no longer referenced."""
    host = await repo.get_host(db, hostname)
    if not host:
        return False

    # Keep track of IDs before deletion
    certificate_ids = [s.certificate_id for s in host.scans if s.certificate_id]
    
    await db.delete(host)
    await db.commit()

    if certificate_ids:
        await cleanup_orphan_certificates(db, certificate_ids)
    return True

async def get_host_or_create(db: AsyncSession, hostname: str):
    """Fetch a host from the database or create it by performing an initial scan if it doesn't exist or is stale."""
    host = await repo.get_host(db, hostname)

    if not host or not is_cache_valid(host.last_scan_at):
        # Trigger a new scan if host doesn't exist or cache is invalid
        try:
            data = await get_or_create_certificate(db, hostname)
            host = data["host"]
        except ScanException:
            # Handle or log error
            return None
            
    return host