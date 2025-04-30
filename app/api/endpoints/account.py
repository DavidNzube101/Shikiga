"""
Shikiga - Account Analysis Endpoint

This module provides the endpoint for analyzing account histories
for potential dusting or address poisoning attacks.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List, Optional

from app.core.detectors.account_analyzer import AccountAnalyzer
from app.db.session import get_db

router = APIRouter()

class AccountRequest(BaseModel):
    """Request model for account analysis"""
    address: str
    start_slot: Optional[int] = None
    end_slot: Optional[int] = None

class EpisodeDetail(BaseModel):
    """Details of a specific suspicious episode"""
    txSig: str
    label: str
    slot: int
    score: Optional[float] = None

class AccountResponse(BaseModel):
    """Response model for account analysis"""
    overall_score: float
    episodes: List[EpisodeDetail]

@router.post("/account", response_model=AccountResponse)
async def analyze_account(
    request: AccountRequest,
    db = Depends(get_db),
    analyzer: AccountAnalyzer = Depends()
):
    """
    Analyze a Solana account's history for potential attacks
    
    - **address**: The Solana account address to analyze
    - **start_slot**: Optional starting block slot for analysis window
    - **end_slot**: Optional ending block slot for analysis window
    
    Returns an overall suspicion score and list of suspicious episodes
    """
    try:
        # Analyze the account history using the analyzer service
        result = await analyzer.analyze_account(
            address=request.address,
            start_slot=request.start_slot,
            end_slot=request.end_slot,
            db=db
        )
        
        return AccountResponse(
            overall_score=result.overall_score,
            episodes=result.episodes
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        # Log the error here
        raise HTTPException(status_code=500, detail="Internal server error")