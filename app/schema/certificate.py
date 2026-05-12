from datetime import datetime
from typing import List, Optional, Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from fastapi import Query

class CertificateRequest(BaseModel):
    """Schema for certificate scan request."""
    url: str
    include_sans: bool = False

class PaginationParams(BaseModel):
    """Common pagination parameters."""
    page: int = Query(1, ge=1, description="Page number")
    page_size: int = Query(10, ge=1, le=100, description="Items per page")

# =========================================================
# HOST
# =========================================================
class HostBase(BaseModel):
    """Base properties for a host."""
    hostname: str
    port: int = 443


class HostCreate(HostBase):
    """Schema for creating a host."""
    pass


class HostResponse(HostBase):
    """Detailed host information for responses."""
    id: int
    created_at: datetime
    

    last_scan_at: Optional[datetime] = None
    last_scan_status: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

# =========================================================
# CERTIFICATE SAN
# =========================================================
class CertificateSANBase(BaseModel):
    """Base properties for Subject Alternative Names."""
    san_value: str


class CertificateSANCreate(CertificateSANBase):
    """Schema for creating a SAN entry."""
    pass


class CertificateSANResponse(CertificateSANBase):
    """SAN information for responses."""
    id: int

    model_config = ConfigDict(from_attributes=True)


# =========================================================
# TLS DETAILS
# =========================================================
class TLSDetailBase(BaseModel):
    """Base properties for TLS connection details."""
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    cipher_protocol: Optional[str] = None
    secret_bits: Optional[int] = None


class TLSDetailCreate(TLSDetailBase):
    """Schema for creating TLS details."""
    pass


class TLSDetailResponse(TLSDetailBase):
    """TLS details for responses."""
    id: int

    model_config = ConfigDict(from_attributes=True)


# =========================================================
# CERTIFICATE CHAIN
# =========================================================
class CertificateChainBase(BaseModel):
    """Base properties for a certificate in a chain."""

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
    """Schema for creating a chain entry."""
    pass


class CertificateChainResponse(CertificateChainBase):
    """Chain entry information for responses."""
    id: int

    model_config = ConfigDict(from_attributes=True)


# =========================================================
# SECURITY CHECKS
# =========================================================
class SecurityCheckBase(BaseModel):
    """Base properties for security status flags."""
    is_expired: bool = False
    expires_soon: bool = False
    strong_tls: bool = False


class SecurityCheckCreate(SecurityCheckBase):
    """Schema for creating security check results."""
    pass


class SecurityCheckResponse(SecurityCheckBase):
    """Security check information for responses."""
    id: int
    checked_at: datetime

    model_config = ConfigDict(from_attributes=True)


# =========================================================
# CERTIFICATE
# =========================================================
class CertificateBase(BaseModel):
    """Base properties for a certificate."""

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
    """Schema for creating a certificate with relations."""

    # REMOVED host_id
    # many-to-many now handled via CertificateScan

    sans: List[CertificateSANCreate] = Field(default_factory=list)

    tls_detail: Optional[TLSDetailCreate] = None

    chain_entries: List[CertificateChainCreate] = Field(default_factory=list)

    security_check: Optional[SecurityCheckCreate] = None


class CertificateUpdate(BaseModel):
    """Schema for updating certificate fields."""

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
    """Certificate information with related data."""
    id: int
    created_at: datetime

    tls_detail: Optional[TLSDetailResponse] = None
    chain_entries: List[CertificateChainResponse] = Field(default_factory=list)
    security_check: Optional[SecurityCheckResponse] = None

    model_config = ConfigDict(from_attributes=True)


class CertificateFullResponse(CertificateResponse):
    """Certificate information including SANs."""
    sans: Optional[List[CertificateSANResponse]] = None



# =========================================================
# CERTIFICATE SCAN
# =========================================================
class CertificateScanBase(BaseModel):
    """Base properties for a scan record."""

    host_id: int
    certificate_id: int

    raw_json: Optional[Any] = None


class CertificateScanCreate(CertificateScanBase):
    """Schema for creating a scan record."""
    pass


class CertificateScanResponse(CertificateScanBase):
    """Scan record information for responses."""

    id: int
    scanned_at: datetime

    model_config = ConfigDict(from_attributes=True)


# =========================================================
# HOST WITH CERTIFICATES
# =========================================================
class HostWithCertificatesResponse(BaseModel):
    """Response containing host and its latest certificate."""
    success: bool = True
    cached: Optional[bool] = None
    error: Optional[str] = None
    host: Optional[HostResponse] = None
    certificate: Optional[CertificateResponse] = None
    model_config = ConfigDict(from_attributes=True)


class HostWithCertificatesFullResponse(HostWithCertificatesResponse):
    """Full response including certificate SANs."""
    certificate: Optional[CertificateFullResponse] = None