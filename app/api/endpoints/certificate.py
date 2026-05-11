from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from pydantic import BaseModel

from app.core.database import get_db

from app.models import (
    Host,
    Certificate,
    TLSDetail,
    CertificateChain,
    SecurityCheck,
    CertificateScan,
)

from app.services.certificate_service import (
    get_or_create_certificate,
)

from app.schema.certificate import (
    HostWithCertificatesResponse,
    CertificateResponse,
    TLSDetailResponse,
    CertificateChainResponse,
    SecurityCheckResponse,
    CertificateScanResponse,
)


router = APIRouter(
    prefix="/certificates",
    tags=["certificates"],
)


# =========================================================
# REQUEST
# =========================================================
class CertificateRequest(BaseModel):
    url: str


# =========================================================
# CHECK + SCAN CERTIFICATE
# =========================================================
@router.post(
    "/check",
    response_model=HostWithCertificatesResponse,
)
def check_certificate(
    request: CertificateRequest,
    db: Session = Depends(get_db),
):
    try:
        host = get_or_create_certificate(
            db,
            request.url,
        )

        return host

    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=str(e),
        )


# =========================================================
# GET HOST
# =========================================================
def get_host_or_404(
    db: Session,
    hostname: str,
) -> Host:

    host = (
        db.query(Host)
        .filter(Host.hostname == hostname)
        .first()
    )

    if not host:
        raise HTTPException(
            status_code=404,
            detail="Host not found",
        )

    return host


# =========================================================
# GET CERTIFICATE DETAILS BY HOSTNAME
# =========================================================
@router.get(
    "/{hostname}",
    response_model=list[CertificateResponse],
)
def get_certificates_by_hostname(
    hostname: str,
    db: Session = Depends(get_db),
):
    host = get_host_or_404(
        db,
        hostname,
    )

    return host.certificates


# =========================================================
# GET TLS DETAILS BY HOSTNAME
# =========================================================
@router.get(
    "/{hostname}/tls",
    response_model=list[TLSDetailResponse],
)
def get_tls_details_by_hostname(
    hostname: str,
    db: Session = Depends(get_db),
):
    host = get_host_or_404(
        db,
        hostname,
    )

    tls_list = []

    for cert in host.certificates:

        if cert.tls_detail:
            tls_list.append(cert.tls_detail)

    return tls_list


# =========================================================
# GET SECURITY CHECKS BY HOSTNAME
# =========================================================
@router.get(
    "/{hostname}/security",
    response_model=list[SecurityCheckResponse],
)
def get_security_by_hostname(
    hostname: str,
    db: Session = Depends(get_db),
):
    host = get_host_or_404(
        db,
        hostname,
    )

    security_list = []

    for cert in host.certificates:

        if cert.security_check:
            security_list.append(
                cert.security_check
            )

    return security_list


# =========================================================
# GET CERTIFICATE CHAIN BY HOSTNAME
# =========================================================
@router.get(
    "/{hostname}/chain",
    response_model=list[CertificateChainResponse],
)
def get_chain_by_hostname(
    hostname: str,
    db: Session = Depends(get_db),
):
    host = get_host_or_404(
        db,
        hostname,
    )

    chain_entries = []

    for cert in host.certificates:
        chain_entries.extend(
            cert.chain_entries
        )

    return chain_entries


# =========================================================
# GET CERTIFICATE SCANS BY HOSTNAME
# =========================================================
@router.get(
    "/{hostname}/scans",
    response_model=list[CertificateScanResponse],
)
def get_scans_by_hostname(
    hostname: str,
    db: Session = Depends(get_db),
):
    host = get_host_or_404(
        db,
        hostname,
    )

    return host.scans