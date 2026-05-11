# Certificate Chain Model

from sqlalchemy import Column, Integer, Text, ForeignKey, DateTime, String
from sqlalchemy.orm import relationship

from app.core.database import Base


class CertificateChain(Base):
    __tablename__ = "certificate_chain"

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

    chain_position = Column(
        Integer,
        nullable=False,
    )

    serial_number = Column(Text)

    # Subject
    subject_common_name = Column(Text)
    subject_organization = Column(Text)
    subject_country = Column(String(2))

    # Issuer
    issuer_common_name = Column(Text)
    issuer_organization = Column(Text)
    issuer_country = Column(String(2))

    # Validity
    not_before = Column(DateTime(timezone=True))
    not_after = Column(DateTime(timezone=True))

    days_left = Column(Integer)

    # Relationships
    certificate = relationship(
        "Certificate",
        back_populates="chain_entries",
    )
