"""
Shikiga - Heuristic Detectors Module

Implements rule-based and heuristic detection methods for
identifying suspicious transactions.
"""
from typing import Dict, Any, List, Optional
import re

from app.core.detectors.base_detector import BaseDetector, DetectionResult
from app.core.reputation.store import ReputationStore

class ValueThresholdDetector(BaseDetector):
    """
    Detects transactions with suspiciously small values (dust)
    """
    
    def __init__(self, dust_threshold: float = 0.01):
        """
        Initialize with configurable dust threshold
        
        Args:
            dust_threshold: Maximum SOL value to be considered dust
        """
        super().__init__("value_threshold")
        self.dust_threshold = dust_threshold
    
    async def detect(
        self, 
        transaction_data: Dict[str, Any], 
        slot: Optional[int] = None
    ) -> DetectionResult:
        """
        Check if transaction value is below dust threshold
        """
        value = self._get_transaction_value(transaction_data)
        
        if value <= 0:
            # Ignore zero or negative values
            return DetectionResult(
                detector_name=self.name,
                detected=False,
                score=0.0,
                reasons=[]
            )
        
        if value < self.dust_threshold:
            # Calculate score based on how small the value is
            # Smaller values are more suspicious
            suspicion_score = 1.0 - (value / self.dust_threshold)
            
            return DetectionResult(
                detector_name=self.name,
                detected=True,
                score=suspicion_score,
                reasons=["value_below_threshold"]
            )
        
        return DetectionResult(
            detector_name=self.name,
            detected=False,
            score=0.0,
            reasons=[]
        )

class FrequencyDetector(BaseDetector):
    """
    Detects high-frequency transactions from the same sender
    """
    
    def __init__(self, reputation_store: ReputationStore, time_window: int = 3600):
        """
        Initialize with reputation store and time window
        
        Args:
            reputation_store: Store tracking sender activity
            time_window: Time window in seconds to consider for frequency
        """
        super().__init__("frequency")
        self.reputation_store = reputation_store
        self.time_window = time_window
    
    async def detect(
        self, 
        transaction_data: Dict[str, Any], 
        slot: Optional[int] = None
    ) -> DetectionResult:
        """
        Check if sender has abnormally high transaction frequency
        """
        sender = self._extract_sender(transaction_data)
        
        if not sender:
            return DetectionResult(
                detector_name=self.name,
                detected=False,
                score=0.0,
                reasons=[]
            )
        
        # Get recent transaction count for this sender
        tx_count = await self.reputation_store.get_recent_tx_count(
            sender, 
            self.time_window
        )
        
        # Record this transaction
        if slot:
            await self.reputation_store.record_transaction(sender, slot)
        
        # Determine if frequency is suspicious
        # Thresholds can be adjusted based on empirical data
        if tx_count > 50:  # Extremely high frequency
            return DetectionResult(
                detector_name=self.name,
                detected=True,
                score=0.95,
                reasons=["extreme_sender_frequency"]
            )
        elif tx_count > 20:  # High frequency
            return DetectionResult(
                detector_name=self.name,
                detected=True,
                score=0.75,
                reasons=["high_sender_frequency"]
            )
        elif tx_count > 10:  # Moderate frequency
            return DetectionResult(
                detector_name=self.name,
                detected=True,
                score=0.5,
                reasons=["moderate_sender_frequency"]
            )
        
        return DetectionResult(
            detector_name=self.name,
            detected=False,
            score=0.0,
            reasons=[]
        )
    
    def _extract_sender(self, transaction_data: Dict[str, Any]) -> Optional[str]:
        """Extract sender address from transaction data"""
        try:
            if "message" in transaction_data and "accountKeys" in transaction_data["message"]:
                return transaction_data["message"]["accountKeys"][0]
        except (KeyError, IndexError):
            pass
        return None

class MemoPatternDetector(BaseDetector):
    """
    Detects suspicious patterns in transaction memos
    """
    
    def __init__(self):
        """Initialize with known suspicious patterns"""
        super().__init__("memo_pattern")
        
        # Compile regex patterns for known suspicious memos
        self.patterns = [
            # Airdrop/marketing patterns
            re.compile(r"(?i)(airdrop|claim|free|bonus|reward)", re.IGNORECASE),
            # URLs in memos (often phishing)
            re.compile(r"https?://[^\s]+\.[^\s]+"),
            # Wallet connection requests
            re.compile(r"(?i)(connect|verify|sync|validate)\s+(wallet|account)"),
        ]
    
    async def detect(
        self, 
        transaction_data: Dict[str, Any], 
        slot: Optional[int] = None
    ) -> DetectionResult:
        """
        Check if transaction memo contains suspicious patterns
        """
        memo = self._extract_memo(transaction_data)
        
        if not memo:
            return DetectionResult(
                detector_name=self.name,
                detected=False,
                score=0.0,
                reasons=[]
            )
        
        # Check against patterns
        matched_patterns = []
        for pattern in self.patterns:
            if pattern.search(memo):
                matched_patterns.append(pattern.pattern)
        
        if matched_patterns:
            return DetectionResult(
                detector_name=self.name,
                detected=True,
                score=0.85,
                reasons=["suspicious_memo_content"]
            )
        
        return DetectionResult(
            detector_name=self.name,
            detected=False,
            score=0.0,
            reasons=[]
        )
    
    def _extract_memo(self, transaction_data: Dict[str, Any]) -> Optional[str]:
        """Extract memo field from transaction data"""
        try:
            # Implementation depends on Solana transaction structure
            # This is a simplified example
            if "message" in transaction_data and "instructions" in transaction_data["message"]:
                for instruction in transaction_data["message"]["instructions"]:
                    # Check if this is a memo program instruction
                    program_id = instruction.get("programId")
                    if program_id == "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr":
                        return instruction.get("data", "")
        except Exception:
            pass
        return None

class AddressSimilarityDetector(BaseDetector):
    """
    Detects address poisoning attempts by identifying similar-looking addresses
    """
    
    def __init__(self):
        """Initialize with address similarity threshold"""
        super().__init__("address_similarity")
        self.similarity_threshold = 0.8  # Match threshold (0-1)
    
    async def detect(
        self, 
        transaction_data: Dict[str, Any], 
        slot: Optional[int] = None
    ) -> DetectionResult:
        """
        Check if transaction involves addresses designed to look similar
        """
        sender, receiver = self._extract_addresses(transaction_data)
        
        if not sender or not receiver:
            return DetectionResult(
                detector_name=self.name,
                detected=False,
                score=0.0,
                reasons=[]
            )
        
        # Check for address similarity patterns common in poisoning attacks
        similarity_score = self._calculate_similarity(sender, receiver)
        
        if similarity_score > self.similarity_threshold:
            return DetectionResult(
                detector_name=self.name,
                detected=True,
                score=similarity_score,
                reasons=["similar_address"]
            )
        
        return DetectionResult(
            detector_name=self.name,
            detected=False,
            score=0.0,
            reasons=[]
        )
    
    def _extract_addresses(self, transaction_data: Dict[str, Any]) -> tuple:
        """Extract sender and receiver addresses from transaction data"""
        sender = None
        receiver = None
        
        try:
            if "message" in transaction_data and "accountKeys" in transaction_data["message"]:
                keys = transaction_data["message"]["accountKeys"]
                if len(keys) >= 2:
                    sender = keys[0]
                    receiver = keys[1]
        except Exception:
            pass
            
        return sender, receiver
    
    def _calculate_similarity(self, addr1: str, addr2: str) -> float:
        """
        Calculate similarity between two addresses
        
        Implements specialized similarity detection for address poisoning,
        focusing on patterns like matching prefixes/suffixes
        """
        if not addr1 or not addr2:
            return 0.0
            
        # Check for same prefix and suffix (common in poisoning)
        prefix_length = 4  # First few characters
        suffix_length = 4  # Last few characters
        
        if (len(addr1) >= prefix_length + suffix_length and 
            len(addr2) >= prefix_length + suffix_length):
            
            prefix_match = addr1[:prefix_length] == addr2[:prefix_length]
            suffix_match = addr1[-suffix_length:] == addr2[-suffix_length:]
            
            if prefix_match and suffix_match:
                return 0.9  # Very high similarity score
            elif prefix_match or suffix_match:
                return 0.7  # Moderate similarity score
        
        # Fall back to simple character-based similarity
        common_chars = sum(c1 == c2 for c1, c2 in zip(addr1, addr2))
        max_length = max(len(addr1), len(addr2))
        
        return common_chars / max_length if max_length > 0 else 0.0