"""Config Review Studio — Analysis Engine (FastAPI)."""

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware

from app.config import CORS_ORIGINS, ENGINE_API_KEY
from app.api.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    CompareRequest,
    CompareResponse,
    NLQueryRequest,
    NLQueryResponse,
    VendorDetection,
)
from app.api.routes import router as api_router

app = FastAPI(
    title="Optimesh Config Review Studio Engine",
    version="0.1.0",
    description="Network configuration analysis engine — vendor-aware linting, "
    "security checks, compliance tagging, and natural language queries.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "config-studio-engine"}
