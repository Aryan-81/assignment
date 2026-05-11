# app/models/certificate.py

from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    Boolean,
    ForeignKey,
    UniqueConstraint,
    DateTime,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.core.database import Base


# =========================================
# HOSTS
# =========================================
class Host(Base):
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, index=True)

    hostname = Column(String(255), nullable=False)
    port = Column(Integer, nullable=False, default=443)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("hostname", "port", name="uq_hostname_port"),
    )

    # Relationships
    certificates = relationship(
        "Certificate",
        back_populates="host",
        cascade="all, delete-orphan",
    )

    scans = relationship(
        "CertificateScan",
        back_populates="host",
        cascade="all, delete-orphan",
    )


# =========================================
# CERTIFICATES
# =========================================
class Certificate(Base):
    __tablename__ = "certificates"

    id = Column(Integer, primary_key=True, index=True)

    host_id = Column(
        Integer,
        ForeignKey("hosts.id", ondelete="CASCADE"),
        nullable=False,
    )

    serial_number = Column(Text, nullable=False, unique=True)

    # Subject
    subject_common_name = Column(Text)
    subject_organization = Column(Text)
    subject_country = Column(String(2))

    # Issuer
    issuer_common_name = Column(Text)
    issuer_organization = Column(Text)
    issuer_country = Column(String(2))

    not_before = Column(DateTime(timezone=True), nullable=False)
    not_after = Column(DateTime(timezone=True), nullable=False)

    days_left = Column(Integer)

    fingerprint_sha256 = Column(Text)
    fingerprint_sha1 = Column(Text)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )

    # Relationships
    host = relationship("Host", back_populates="certificates")

    sans = relationship(
        "CertificateSAN",
        back_populates="certificate",
        cascade="all, delete-orphan",
    )

    tls_detail = relationship(
        "TLSDetail",
        back_populates="certificate",
        uselist=False,
        cascade="all, delete-orphan",
    )

    chain_entries = relationship(
        "CertificateChain",
        back_populates="certificate",
        cascade="all, delete-orphan",
    )

    security_check = relationship(
        "SecurityCheck",
        back_populates="certificate",
        uselist=False,
        cascade="all, delete-orphan",
    )

    scans = relationship(
        "CertificateScan",
        back_populates="certificate",
        cascade="all, delete-orphan",
    )


# =========================================
# CERTIFICATE SANs
# =========================================
class CertificateSAN(Base):
    __tablename__ = "certificate_sans"

    id = Column(Integer, primary_key=True, index=True)

    certificate_id = Column(
        Integer,
        ForeignKey("certificates.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    san_value = Column(Text, nullable=False)

    # Relationships
    certificate = relationship(
        "Certificate",
        back_populates="sans",
    )


# =========================================
# TLS DETAILS
# =========================================
class TLSDetail(Base):
    __tablename__ = "tls_details"

    id = Column(Integer, primary_key=True, index=True)

    certificate_id = Column(
        Integer,
        ForeignKey("certificates.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )

    tls_version = Column(String(50))
    cipher_suite = Column(Text)
    cipher_protocol = Column(String(50))
    secret_bits = Column(Integer)

    # Relationships
    certificate = relationship(
        "Certificate",
        back_populates="tls_detail",
    )


# =========================================
# CERTIFICATE CHAIN
# =========================================
class CertificateChain(Base):
    __tablename__ = "certificate_chain"

    id = Column(Integer, primary_key=True, index=True)

    certificate_id = Column(
        Integer,
        ForeignKey("certificates.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    chain_position = Column(Integer, nullable=False)

    serial_number = Column(Text)

    # Subject
    subject_common_name = Column(Text)
    subject_organization = Column(Text)
    subject_country = Column(String(2))

    # Issuer
    issuer_common_name = Column(Text)
    issuer_organization = Column(Text)
    issuer_country = Column(String(2))

    not_before = Column(DateTime(timezone=True))
    not_after = Column(DateTime(timezone=True))

    days_left = Column(Integer)

    # Relationships
    certificate = relationship(
        "Certificate",
        back_populates="chain_entries",
    )


# =========================================
# SECURITY CHECKS
# =========================================
class SecurityCheck(Base):
    __tablename__ = "security_checks"

    id = Column(Integer, primary_key=True, index=True)

    certificate_id = Column(
        Integer,
        ForeignKey("certificates.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )

    is_expired = Column(Boolean, default=False)
    expires_soon = Column(Boolean, default=False)
    strong_tls = Column(Boolean, default=False)

    checked_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    # Relationships
    certificate = relationship(
        "Certificate",
        back_populates="security_check",
    )


# =========================================
# CERTIFICATE SCANS
# =========================================
class CertificateScan(Base):
    __tablename__ = "certificate_scans"

    id = Column(Integer, primary_key=True, index=True)

    host_id = Column(
        Integer,
        ForeignKey("hosts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    certificate_id = Column(
        Integer,
        ForeignKey("certificates.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    scanned_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    raw_json = Column(JSONB)

    # Relationships
    host = relationship(
        "Host",
        back_populates="scans",
    )

    certificate = relationship(
        "Certificate",
        back_populates="scans",
    )