# TLS Detail Model

from sqlalchemy import Column, Integer, String, Text, ForeignKey
from sqlalchemy.orm import relationship

from app.core.database import Base


class TLSDetail(Base):
    """Detailed TLS connection parameters (version, cipher) for a specific certificate scan."""
    __tablename__ = "tls_details"

    id = Column(Integer, primary_key=True, index=True)

    certificate_id = Column(
        Integer,
        ForeignKey(
            "certificates.id",
            ondelete="CASCADE",
        ),
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
        lazy="selectin",
    )
