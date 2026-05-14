# Certificate Model

from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.core.database import Base


class Certificate(Base):
    """Stores core SSL certificate information extracted during a scan."""
    __tablename__ = "certificates"

    id = Column(Integer, primary_key=True, index=True)

    # serials are NOT globally unique
    serial_number = Column(Text, nullable=False)

    # Subject
    subject_common_name = Column(Text)
    subject_organization = Column(Text)
    subject_country = Column(String(2))

    # Issuer
    issuer_common_name = Column(Text)
    issuer_organization = Column(Text)
    issuer_country = Column(String(2))

    # Validity
    not_before = Column(
        DateTime(timezone=True),
        nullable=False,
    )

    not_after = Column(
        DateTime(timezone=True),
        nullable=False,
    )

    days_left = Column(Integer)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
    )


    # Relationships
    scans = relationship(
        "CertificateScan",
        back_populates="certificate",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    # many-to-many
    hosts = relationship(
        "Host",
        secondary="certificate_scans",
        viewonly=True,
        lazy="selectin",
    )

    sans = relationship(
        "CertificateSAN",
        back_populates="certificate",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    tls_detail = relationship(
        "TLSDetail",
        back_populates="certificate",
        uselist=False,
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    chain_entries = relationship(
        "CertificateChain",
        back_populates="certificate",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    security_check = relationship(
        "SecurityCheck",
        back_populates="certificate",
        uselist=False,
        cascade="all, delete-orphan",
        lazy="selectin",
    )
