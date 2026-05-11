from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.services.certificate_service import get_or_create_certificate
from app.schema.certificate import HostWithCertificatesResponse
from pydantic import BaseModel

router = APIRouter(prefix="/certificates", tags=["certificates"])

class CertificateRequest(BaseModel):
    url: str

@router.post("/check", response_model=HostWithCertificatesResponse)
def check_certificate(request: CertificateRequest, db: Session = Depends(get_db)):
    try:
        host = get_or_create_certificate(db, request.url)
        return host
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
