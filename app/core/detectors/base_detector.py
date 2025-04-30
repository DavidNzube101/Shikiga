"""
Shikiga - Base Detector Module

Defines the base detector interface and common functionality for all
attack detection components.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

@dataclass
class DetectionResult:
    """Container for individual detector results"""
    detector_name: str
    detected: bool
    score: float = 0.0
    reasons: List[str] = None
    
    def __post_init__(self):
        if self.reasons is None:
            self.reasons = []

class BaseDetector(ABC):
    """
    Base class for all detection components
    """
    
    def __init__(self, name: str):
        self.name = name
    
    @abstractmethod
    async def detect(
        self, 
        transaction_data: Dict[str, Any], 
        slot: Optional[int] = None
    ) -> DetectionResult:
        """
        Analyze transaction data for suspicious patterns
        
        Args:
            transaction_data: Parsed transaction data
            slot: Optional block slot number
            
        Returns:
            DetectionResult with detection score and reasons
        """
        pass
    
    def _get_transaction_value(self, transaction_data: Dict[str, Any]) -> float:
        """
        Extract the transaction value in SOL
        
        This is a helper method that subclasses can use.
        Implementation depends on the exact structure of Solana transaction data.
        """
        # Example implementation - would need to be adjusted for actual Solana tx format
        lamports_per_sol = 1_000_000_000  # 1 SOL = 10^9 lamports
        
        try:
            # Extract from preBalances and postBalances in the transaction
            if "meta" in transaction_data and "postBalances" in transaction_data["meta"]:
                pre_balances = transaction_data["meta"].get("preBalances", [])
                post_balances = transaction_data["meta"].get("postBalances", [])
                
                if len(pre_balances) >= 2 and len(post_balances) >= 2:
                    # Assume first account is sender, second is receiver
                    # This is simplified and would need adjustment for multi-account txs
                    sender_pre = pre_balances[0]
                    sender_post = post_balances[0]
                    
                    # Calculate value transferred (excluding fees)
                    value_lamports = sender_pre - sender_post
                    return value_lamports / lamports_per_sol
            
            # Alternative extraction from instructions
            if "message" in transaction_data and "instructions" in transaction_data["message"]:
                for instr in transaction_data["message"]["instructions"]:
                    if "data" in instr:
                        # Parse instruction data for transfer amount
                        # This is highly dependent on the program being called
                        pass
                        
            return 0.0
        except Exception:
            return 0.0