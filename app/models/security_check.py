# Security Check Model

from sqlalchemy import Column, Integer, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.core.database import Base


class SecurityCheck(Base):
    __tablename__ = "security_checks"

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

    is_expired = Column(
        Boolean,
        default=False,
    )

    expires_soon = Column(
        Boolean,
        default=False,
    )

    strong_tls = Column(
        Boolean,
        default=False,
    )

    checked_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
    )


    # Relationships
    certificate = relationship(
        "Certificate",
        back_populates="security_check",
    )
