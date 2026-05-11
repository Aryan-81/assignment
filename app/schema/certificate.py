
from datetime import datetime
from typing import List, Optional, Any

from pydantic import BaseModel, ConfigDict


# HOST
class HostBase(BaseModel):
    hostname: str
    port: int = 443


class HostCreate(HostBase):
    pass


class HostResponse(HostBase):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# CERTIFICATE SAN
class CertificateSANBase(BaseModel):
    san_value: str


class CertificateSANCreate(CertificateSANBase):
    pass


class CertificateSANResponse(CertificateSANBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


# TLS DETAILS
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


# CERTIFICATE CHAIN
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


# SECURITY CHECKS
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


# CERTIFICATE
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

    not_before: datetime
    not_after: datetime

    days_left: Optional[int] = None

    fingerprint_sha256: Optional[str] = None
    fingerprint_sha1: Optional[str] = None


class CertificateCreate(CertificateBase):
    host_id: int

    sans: List[CertificateSANCreate] = []

    tls_detail: Optional[TLSDetailCreate] = None

    chain_entries: List[CertificateChainCreate] = []

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

    fingerprint_sha256: Optional[str] = None
    fingerprint_sha1: Optional[str] = None


class CertificateResponse(CertificateBase):
    id: int
    host_id: int

    created_at: datetime
    updated_at: datetime

    sans: List[CertificateSANResponse] = []

    tls_detail: Optional[TLSDetailResponse] = None

    chain_entries: List[CertificateChainResponse] = []

    security_check: Optional[SecurityCheckResponse] = None

    model_config = ConfigDict(from_attributes=True)


# CERTIFICATE SCAN
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


# FULL HOST RESPONSE
class HostWithCertificatesResponse(HostResponse):
    certificates: List[CertificateResponse] = []

    model_config = ConfigDict(from_attributes=True)