"""
Shikiga - Transaction Analysis Endpoint

This module provides the endpoint for analyzing individual transactions
for potential dusting or address poisoning attacks.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List, Optional

from app.core.detectors.transaction_analyzer import TransactionAnalyzer
from app.db.session import get_db

router = APIRouter()

class TransactionRequest(BaseModel):
    """Request model for transaction analysis"""
    transaction: str  # Base64-encoded transaction
    slot: Optional[int] = None

class TransactionResponse(BaseModel):
    """Response model for transaction analysis"""
    score: float
    labels: List[str]
    reasons: List[str]

@router.post("/transaction", response_model=TransactionResponse)
async def analyze_transaction(
    request: TransactionRequest,
    db = Depends(get_db),
    analyzer: TransactionAnalyzer = Depends()
):
    """
    Analyze a single Solana transaction for potential attacks
    
    - **transaction**: Base64-encoded transaction message
    - **slot**: Optional block slot where the transaction was included
    
    Returns a suspicion score, attack labels, and reasons for the classification
    """
    try:
        # Analyze the transaction using the analyzer service
        result = await analyzer.analyze(
            transaction=request.transaction,
            slot=request.slot,
            db=db
        )
        
        return TransactionResponse(
            score=result.score,
            labels=result.labels,
            reasons=result.reasons
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        # Log the error here
        raise HTTPException(status_code=500, detail="Internal server error")