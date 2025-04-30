"""
Shikiga - Configuration settings for the application.

This module handles loading configuration from environment variables
and provides defaults.
"""
import os
from typing import List
from pydantic import BaseSettings

class Settings(BaseSettings):
    """Application settings"""
    
    # API settings
    API_VERSION: str = "v1"
    VERSION: str = "1.0.0"
    PROJECT_NAME: str = "Solana Attack Detection API"
    
    # CORS settings
    CORS_ORIGINS: List[str] = ["*"]
    
    # Database settings
    MONGODB_URL: str = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
    DATABASE_NAME: str = os.getenv("DATABASE_NAME", "solana_attack_detection")
    
    # Redis settings
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    
    # Detection settings
    DUST_THRESHOLD: float = float(os.getenv("DUST_THRESHOLD", "0.01"))  # SOL
    
    # ML model path
    MODEL_PATH: str = os.getenv("MODEL_PATH", "models/anomaly_detector.pkl")
    
    class Config:
        env_file = ".env"

# Create global settings object
settings = Settings()