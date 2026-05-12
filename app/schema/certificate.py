from datetime import datetime
from typing import List, Optional, Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from fastapi import Query

class CertificateRequest(BaseModel):
    url: str
    include_sans: bool = False

class PaginationParams(BaseModel):
    page: int = Query(1, ge=1, description="Page number")
    page_size: int = Query(10, ge=1, le=100, description="Items per page")

# =========================================================
# HOST
# =========================================================
class HostBase(BaseModel):
    hostname: str
    port: int = 443


class HostCreate(HostBase):
    pass


class HostResponse(HostBase):
    id: int
    created_at: datetime
    

    last_scan_at: Optional[datetime] = None
    last_scan_status: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

# =========================================================
# CERTIFICATE SAN
# =========================================================
class CertificateSANBase(BaseModel):
    san_value: str


class CertificateSANCreate(CertificateSANBase):
    pass


class CertificateSANResponse(CertificateSANBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


# =========================================================
# TLS DETAILS
# =========================================================
class TLSDetailBase(BaseModel):
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    cipher_protocol: Optional[str] = None
    secret_bits: Optional[int] = None


class TLSDetailCreate(TLSDetailBase):
    pass


class TLSDetailResponse(TLSDetailBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


# =========================================================
# CERTIFICATE CHAIN
# =========================================================
class CertificateChainBase(BaseModel):

    chain_position: int

    serial_number: Optional[str] = None

    # Subject
    subject_common_name: Optional[str] = None
    subject_organization: Optional[str] = None
    subject_country: Optional[str] = None

    # Issuer
    issuer_common_name: Optional[str] = None
    issuer_organization: Optional[str] = None
    issuer_country: Optional[str] = None

    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None

    days_left: Optional[int] = None


class CertificateChainCreate(CertificateChainBase):
    pass


class CertificateChainResponse(CertificateChainBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


# =========================================================
# SECURITY CHECKS
# =========================================================
class SecurityCheckBase(BaseModel):
    is_expired: bool = False
    expires_soon: bool = False
    strong_tls: bool = False


class SecurityCheckCreate(SecurityCheckBase):
    pass


class SecurityCheckResponse(SecurityCheckBase):
    id: int
    checked_at: datetime

    model_config = ConfigDict(from_attributes=True)


# =========================================================
# CERTIFICATE
# =========================================================
class CertificateBase(BaseModel):

    serial_number: str

    # Subject
    subject_common_name: Optional[str] = None
    subject_organization: Optional[str] = None
    subject_country: Optional[str] = None

    # Issuer
    issuer_common_name: Optional[str] = None
    issuer_organization: Optional[str] = None
    issuer_country: Optional[str] = None

    # Validity
    not_before: datetime
    not_after: datetime

    days_left: Optional[int] = None



class CertificateCreate(CertificateBase):

    # REMOVED host_id
    # many-to-many now handled via CertificateScan

    sans: List[CertificateSANCreate] = Field(default_factory=list)

    tls_detail: Optional[TLSDetailCreate] = None

    chain_entries: List[CertificateChainCreate] = Field(default_factory=list)

    security_check: Optional[SecurityCheckCreate] = None


class CertificateUpdate(BaseModel):

    subject_common_name: Optional[str] = None
    subject_organization: Optional[str] = None
    subject_country: Optional[str] = None

    issuer_common_name: Optional[str] = None
    issuer_organization: Optional[str] = None
    issuer_country: Optional[str] = None

    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None

    days_left: Optional[int] = None



class CertificateResponse(CertificateBase):
    id: int
    created_at: datetime

    tls_detail: Optional[TLSDetailResponse] = None
    chain_entries: List[CertificateChainResponse] = Field(default_factory=list)
    security_check: Optional[SecurityCheckResponse] = None

    model_config = ConfigDict(from_attributes=True)


class CertificateFullResponse(CertificateResponse):
    sans: Optional[List[CertificateSANResponse]] = None



# =========================================================
# CERTIFICATE SCAN
# =========================================================
class CertificateScanBase(BaseModel):

    host_id: int
    certificate_id: int

    raw_json: Optional[Any] = None


class CertificateScanCreate(CertificateScanBase):
    pass


class CertificateScanResponse(CertificateScanBase):

    id: int
    scanned_at: datetime

    model_config = ConfigDict(from_attributes=True)


# =========================================================
# HOST WITH CERTIFICATES
# =========================================================
class HostWithCertificatesResponse(BaseModel):
    success: bool = True
    cached: Optional[bool] = None
    error: Optional[str] = None
    host: Optional[HostResponse] = None
    certificate: Optional[CertificateResponse] = None
    model_config = ConfigDict(from_attributes=True)


class HostWithCertificatesFullResponse(HostWithCertificatesResponse):
    certificate: Optional[CertificateFullResponse] = None