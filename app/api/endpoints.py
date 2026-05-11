from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schema.certificate import (
    HostWithCertificatesResponse,
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

@router.post("/check", response_model=HostWithCertificatesResponse)
def check_certificate(request: CertificateRequest, db: Session = Depends(get_db)):
    try:
        return cert_svc.get_or_create_certificate(db, str(request.url))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@router.post("/check_no_cache", response_model=HostWithCertificatesResponse)
def check_certificate_no_cache(request: CertificateRequest, db: Session = Depends(get_db)):
    try:
        return cert_svc.get_certificate_no_cache(db, str(request.url))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/", response_model=list[HostWithCertificatesResponse])
def get_all_domains(pagination: PaginationParams = Depends(), db: Session = Depends(get_db)):
    return host_svc.get_paginated_hosts_with_latest_scan(db, pagination.page, pagination.page_size)

@router.get("/{hostname}", response_model=list[CertificateResponse])
def get_certificates_by_hostname(hostname: str, db: Session = Depends(get_db)):
    host = host_svc.get_host_or_create(db, hostname)
    return host.certificates

@router.get("/{hostname}/tls", response_model=list[TLSDetailResponse])
def get_tls_details_by_hostname(hostname: str, db: Session = Depends(get_db)):
    host = host_svc.get_host_or_create(db, hostname)
    return get_related_objects(host, "tls_detail")

@router.get("/{hostname}/security", response_model=list[SecurityCheckResponse])
def get_security_by_hostname(hostname: str, db: Session = Depends(get_db)):
    host = host_svc.get_host_or_create(db, hostname)
    return get_related_objects(host, "security_check")

@router.get("/{hostname}/chain", response_model=list[CertificateChainResponse])
def get_chain_by_hostname(hostname: str, db: Session = Depends(get_db)):
    host = host_svc.get_host_or_create(db, hostname)
    # Flatten chain entries from all certificates
    return [entry for cert in host.certificates for entry in cert.chain_entries]

@router.get("/{hostname}/scans", response_model=list[CertificateScanResponse])
def get_scans_by_hostname(hostname: str, db: Session = Depends(get_db)):
    host = host_svc.get_host_or_create(db, hostname)
    return host.scans

@router.delete("/{hostname}", status_code=status.HTTP_204_NO_CONTENT)
def delete_domain(hostname: str, db: Session = Depends(get_db)):
    host_svc.delete_host_and_orphans(db, hostname)
    return None