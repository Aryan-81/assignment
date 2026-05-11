from fastapi import FastAPI
from pydantic import BaseModel

from app.core.database import Base, engine

app = FastAPI()


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)


class User(BaseModel):
    name: str
    age: int


@app.get("/")
def home():
    return {"status": "running"}