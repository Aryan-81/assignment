# Host Model

from sqlalchemy import Column, Integer, String, DateTime, UniqueConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.core.database import Base


class Host(Base):
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, index=True)

    hostname = Column(String(255), nullable=False)
    port = Column(Integer, nullable=False, default=443)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    __table_args__ = (
        UniqueConstraint(
            "hostname",
            "port",
            name="uq_hostname_port",
        ),
    )

    # Relationships
    scans = relationship(
        "CertificateScan",
        back_populates="host",
        cascade="all, delete-orphan",
    )

    # many-to-many (read only)
    certificates = relationship(
        "Certificate",
        secondary="certificate_scans",
        viewonly=True,
    )
