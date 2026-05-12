# Certificate Scan Model

from sqlalchemy import Column, Integer, ForeignKey, DateTime, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.core.database import Base


class CertificateScan(Base):
    """Recorded scan event linking a host to a certificate at a specific point in time."""
    __tablename__ = "certificate_scans"

    id = Column(Integer, primary_key=True, index=True)

    host_id = Column(
        Integer,
        ForeignKey(
            "hosts.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    certificate_id = Column(
        Integer,
        ForeignKey(
            "certificates.id",
            ondelete="CASCADE",
        ),
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

    # prevent duplicate scan rows
    __table_args__ = (
        UniqueConstraint(
            "host_id",
            "certificate_id",
            name="uq_host_certificate",
        ),
    )
