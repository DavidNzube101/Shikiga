"""
Shikiga - Health Check Endpoint

This module provides a health check endpoint for monitoring
system status and version information.
"""
from fastapi import APIRouter
from pydantic import BaseModel

from app.core.config import settings

router = APIRouter()

class HealthResponse(BaseModel):
    """Response model for health check"""
    status: str
    version: str

@router.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Check API health status
    
    Returns status and version information
    """
    return HealthResponse(
        status="ok",
        version=settings.VERSION
    )