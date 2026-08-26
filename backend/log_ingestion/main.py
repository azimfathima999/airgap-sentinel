from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.log_ingestion.routes import router
from backend.log_ingestion.database import Base, engine

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Airgap Sentinel Log Ingestion API",
    description="API for ingesting and managing logs in airgapped environments",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/")
async def root():
    return {"message": "Airgap Sentinel Log Ingestion API v0.1.0"}


@app.get("/health")
async def health_check():
    return {"status": "ok"}
