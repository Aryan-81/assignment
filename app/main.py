from fastapi import FastAPI
from app.api.endpoints import certificate
from app.core.database import Base, engine

app = FastAPI(title="SSL Certificate Checker")

# Include Routers
app.include_router(certificate.router)

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)


@app.get("/")
def home():
    return {"status": "running", "message": "SSL Certificate Checker API"}