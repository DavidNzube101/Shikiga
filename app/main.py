"""
Solana Attack Detection API - Main Application Entry Point

This module initializes the FastAPI application, configures middleware,
and registers API routes.
"""
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi

from app.api.endpoints import transaction, account, health
from app.core.config import settings
from app.db.session import get_db

app = FastAPI(
    title="Solana Attack Detection API",
    description="API for detecting Solana dusting and address poisoning attacks",
    version="1.0.0",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(transaction.router, prefix="/v1/analyze", tags=["analysis"])
app.include_router(account.router, prefix="/v1/analyze", tags=["analysis"])
app.include_router(health.router, prefix="/v1", tags=["system"])

# Custom OpenAPI schema
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
        
    openapi_schema = get_openapi(
        title="Solana Attack Detection API",
        version="1.0.0",
        description="API for detecting Solana dusting and address poisoning attacks in raw transaction data",
        routes=app.routes,
    )
    
    # Add security scheme if needed
    # openapi_schema["components"]["securitySchemes"] = {...}
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)