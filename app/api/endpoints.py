from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.schema.certificate import (
    HostWithCertificatesResponse,
    HostWithCertificatesFullResponse,
    CertificateResponse,
    TLSDetailResponse,
    CertificateChainResponse,
    SecurityCheckResponse,
    CertificateScanResponse,
    CertificateRequest,
    PaginationParams
)
from app.services import certificate_service as cert_svc
from app.services import host_service as host_svc
from app.utils.helper import get_related_objects

router = APIRouter(prefix="/certificates", tags=["certificates"])

@router.post("/check", response_model=HostWithCertificatesFullResponse, response_model_exclude_none=True)
async def check_certificate(request: CertificateRequest, db: AsyncSession = Depends(get_db)):
    """Scan URL for certificate or fetch from cache."""
    result = await cert_svc.get_or_create_certificate(db, str(request.url))
    if not request.include_sans:
        return HostWithCertificatesResponse.model_validate(result)
    return HostWithCertificatesFullResponse.model_validate(result)

@router.post("/check_no_cache", response_model=HostWithCertificatesFullResponse, response_model_exclude_none=True)
async def check_certificate_no_cache(request: CertificateRequest, db: AsyncSession = Depends(get_db)):
    """Perform a fresh scan bypassing the cache."""
    result = await cert_svc.get_certificate_no_cache(db, str(request.url))
    if not request.include_sans:
        return HostWithCertificatesResponse.model_validate(result)
    return HostWithCertificatesFullResponse.model_validate(result)

@router.get("/", response_model=list[HostWithCertificatesFullResponse])
async def get_all_domains(pagination: PaginationParams = Depends(), db: AsyncSession = Depends(get_db)):
    """List all domains with pagination."""
    return await host_svc.get_paginated_hosts_with_latest_scan(db, pagination.page, pagination.page_size)

@router.get("/{hostname}", response_model=list[CertificateResponse])
async def get_certificates_by_hostname(hostname: str, db: AsyncSession = Depends(get_db)):
    """Get certificates for a specific host."""
    host = await host_svc.get_host_or_create(db, hostname)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    return host.certificates

@router.get("/{hostname}/tls", response_model=list[TLSDetailResponse])
async def get_tls_details_by_hostname(hostname: str, db: AsyncSession = Depends(get_db)):
    """Get TLS details for a specific host."""
    host = await host_svc.get_host_or_create(db, hostname)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    return get_related_objects(host, "tls_detail")

@router.get("/{hostname}/security", response_model=list[SecurityCheckResponse])
async def get_security_by_hostname(hostname: str, db: AsyncSession = Depends(get_db)):
    """Get security checks for a specific host."""
    host = await host_svc.get_host_or_create(db, hostname)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    return get_related_objects(host, "security_check")

@router.get("/{hostname}/chain", response_model=list[CertificateChainResponse])
async def get_chain_by_hostname(hostname: str, db: AsyncSession = Depends(get_db)):
    """Get certificate chain for a specific host."""
    host = await host_svc.get_host_or_create(db, hostname)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    # Flatten chain entries from all certificates
    return [entry for cert in host.certificates for entry in cert.chain_entries]

@router.get("/{hostname}/scans", response_model=list[CertificateScanResponse])
async def get_scans_by_hostname(hostname: str, db: AsyncSession = Depends(get_db)):
    """Get scan history for a specific host."""
    host = await host_svc.get_host_or_create(db, hostname)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    return host.scans

@router.delete("/{hostname}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_domain(hostname: str, db: AsyncSession = Depends(get_db)):
    """Delete a host and its related records."""
    await host_svc.delete_host_and_orphans(db, hostname)
    return None