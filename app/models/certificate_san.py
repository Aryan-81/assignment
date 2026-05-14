# Certificate SAN Model

from sqlalchemy import Column, Integer, Text, ForeignKey
from sqlalchemy.orm import relationship

from app.core.database import Base


class CertificateSAN(Base):
    """Subject Alternative Name (SAN) entries associated with an SSL certificate."""
    __tablename__ = "certificate_sans"

    id = Column(Integer, primary_key=True, index=True)

    certificate_id = Column(
        Integer,
        ForeignKey(
            "certificates.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    san_value = Column(Text, nullable=False)

    certificate = relationship(
        "Certificate",
        back_populates="sans",
        lazy="selectin",
    )
