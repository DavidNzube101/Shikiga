"""
Shikiga - Account Analyzer

Provides analysis of Solana account history to detect patterns of
dusting or address poisoning attacks over time.
"""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from app.core.detectors.transaction_analyzer import TransactionAnalyzer

@dataclass
class EpisodeDetail:
    """Details of a specific suspicious episode"""
    txSig: str
    label: str
    slot: int
    score: float = 0.0

@dataclass
class AccountAnalysisResult:
    """Container for account analysis results"""
    overall_score: float
    episodes: List[EpisodeDetail] = field(default_factory=list)

class AccountAnalyzer:
    """
    Analyzes account history for potential attack patterns
    """
    
    def __init__(
        self,
        transaction_analyzer: TransactionAnalyzer,
        recent_tx_limit: int = 100
    ):
        """
        Initialize with transaction analyzer
        
        Args:
            transaction_analyzer: Analyzer for individual transactions
            recent_tx_limit: Maximum number of recent transactions to analyze
        """
        self.transaction_analyzer = transaction_analyzer
        self.recent_tx_limit = recent_tx_limit
    
    async def analyze_account(
        self, 
        address: str,
        start_slot: Optional[int] = None,
        end_slot: Optional[int] = None,
        db = None
    ) -> AccountAnalysisResult:
        """
        Analyze an account's transaction history for potential attacks
        
        Args:
            address: Solana account address to analyze
            start_slot: Optional starting block slot for analysis window
            end_slot: Optional ending block slot for analysis window
            db: Database connection
            
        Returns:
            AccountAnalysisResult with overall score and suspicious episodes
        """
        # Fetch recent transactions for the account
        transactions = await self._fetch_account_transactions(
            address,
            start_slot,
            end_slot,
            db
        )
        
        if not transactions:
            return AccountAnalysisResult(
                overall_score=0.0,
                episodes=[]
            )
        
        # Analyze each transaction
        suspicious_episodes = []
        total_score = 0.0
        
        for tx in transactions:
            # Skip transactions that don't involve this address directly
            if not self._address_in_transaction(tx, address):
                continue
                
            # Analyze the transaction
            transaction_base64 = tx.get("transaction", "")
            slot = tx.get("slot", 0)
            
            result = await self.transaction_analyzer.analyze(
                transaction=transaction_base64,
                slot=slot,
                db=db
            )
            
            # Record if suspicious
            if result.score > 0.5 and result.labels:
                tx_sig = tx.get("signature", "unknown")
                label = result.labels[0] if result.labels else "suspicious"
                
                suspicious_episodes.append(
                    EpisodeDetail(
                        txSig=tx_sig,
                        label=label,
                        slot=slot,
                        score=result.score
                    )
                )
                
                total_score += result.score
        
        # Calculate overall account score
        num_suspicious = len(suspicious_episodes)
        num_analyzed = len(transactions)
        
        if num_suspicious == 0:
            overall_score = 0.0
        else:
            # Weighted average of episode scores and suspicious ratio
            avg_episode_score = total_score / num_suspicious
            suspicious_ratio = num_suspicious / num_analyzed
            
            overall_score = (avg_episode_score * 0.7) + (suspicious_ratio * 0.3)
            overall_score = min(1.0, overall_score)  # Cap at 1.0
        
        return AccountAnalysisResult(
            overall_score=overall_score,
            episodes=suspicious_episodes
        )
    
    async def _fetch_account_transactions(
        self, 
        address: str,
        start_slot: Optional[int],
        end_slot: Optional[int],
        db
    ) -> List[Dict[str, Any]]:
        """
        Fetch recent transactions for an account
        
        Implementation depends on how Solana transactions are stored/accessed.
        Could use a direct Solana RPC node connection or a database lookup.
        """
        # This is a stub implementation that would need to be replaced
        # with actual Solana transaction fetching logic
        try:
            # Example database query (pseudocode)
            query = {
                "accounts": {"$in": [address]},
            }
            
            if start_slot is not None:
                query["slot"] = {"$gte": start_slot}
                
            if end_slot is not None:
                if "slot" not in query:
                    query["slot"] = {}
                query["slot"]["$lte"] = end_slot
            
            # Execute query against database or Solana RPC
            # For now, return empty list as placeholder
            return []
            
        except Exception as e:
            print(f"Error fetching transactions: {e}")
            return []
    
    def _address_in_transaction(self, tx: Dict[str, Any], address: str) -> bool:
        """Check if address is involved in transaction"""
        try:
            if "accounts" in tx:
                return address in tx["accounts"]
                
            # Check transaction data structure
            if "transaction" in tx and "message" in tx["transaction"]:
                account_keys = tx["transaction"]["message"].get("accountKeys", [])
                return address in account_keys
                
        except Exception:
            pass
            
        return False