# app/models/base.py
from app.core.database import Base
from app.models import (
    Host,
    Certificate,
    CertificateSAN,
    TLSDetail,
    CertificateChain,
    SecurityCheck,
    CertificateScan,
)
