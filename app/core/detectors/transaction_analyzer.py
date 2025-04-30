"""
Shikiga - Transaction Analyzer

Provides analysis of individual Solana transactions to detect
potential dusting and address poisoning attacks.
"""
import base64
import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from app.core.detectors.base_detector import BaseDetector
from app.core.detectors.heuristic import ValueThresholdDetector, FrequencyDetector, MemoPatternDetector
from app.core.detectors.ml import AnomalyDetector
from app.core.reputation.store import ReputationStore

@dataclass
class AnalysisResult:
    """Container for transaction analysis results"""
    score: float
    labels: List[str]
    reasons: List[str]

class TransactionAnalyzer:
    """
    Analyzes individual transactions for potential attacks using multiple detection methods
    """
    
    def __init__(
        self,
        value_detector: ValueThresholdDetector,
        frequency_detector: FrequencyDetector,
        pattern_detector: MemoPatternDetector,
        anomaly_detector: AnomalyDetector,
        reputation_store: ReputationStore
    ):
        self.detectors = [
            value_detector,
            frequency_detector,
            pattern_detector,
            anomaly_detector
        ]
        self.reputation_store = reputation_store
        
        # Thresholds for labeling
        self.dusting_threshold = 0.7
        self.poisoning_threshold = 0.75
        
    async def analyze(
        self, 
        transaction: str, 
        slot: Optional[int] = None,
        db = None
    ) -> AnalysisResult:
        """
        Analyze a transaction for potential attacks
        
        Args:
            transaction: Base64-encoded transaction
            slot: Block slot where the transaction was included
            db: Database connection
            
        Returns:
            AnalysisResult with score, labels and reasons
        """
        # Decode and parse the transaction
        try:
            tx_data = self._decode_transaction(transaction)
        except Exception as e:
            raise ValueError(f"Failed to decode transaction: {str(e)}")
        
        # Check sender reputation
        sender = self._extract_sender(tx_data)
        reputation_score = await self.reputation_store.get_score(sender)
        
        # Apply all detectors
        detection_results = []
        for detector in self.detectors:
            result = await detector.detect(tx_data, slot)
            if result.detected:
                detection_results.append(result)
        
        # Calculate overall score (weighted average)
        weights = {
            'value_threshold': 0.2,
            'frequency': 0.3,
            'memo_pattern': 0.25,
            'anomaly': 0.25
        }
        
        score = 0.0
        reasons = []
        for result in detection_results:
            score += result.score * weights.get(result.detector_name, 0.25)
            reasons.extend(result.reasons)
        
        # Apply reputation adjustment
        score = (score * 0.8) + ((1 - reputation_score) * 0.2)
        
        # Determine labels based on score and specific patterns
        labels = self._determine_labels(score, detection_results)
        
        # Store result for future reference if db provided
        if db and slot:
            await self._store_result(db, tx_data, score, labels, slot)
        
        # Update reputation if highly suspicious
        if score > 0.8:
            await self.reputation_store.update_score(sender, max(0.1, reputation_score - 0.2))
        
        return AnalysisResult(
            score=min(1.0, score),  # Cap at 1.0
            labels=labels,
            reasons=list(set(reasons))  # Remove duplicates
        )
    
    def _decode_transaction(self, transaction: str) -> Dict[str, Any]:
        """Decode base64 transaction into structured data"""
        try:
            # First try decoding directly as JSON
            try:
                return json.loads(transaction)
            except json.JSONDecodeError:
                # If not JSON, try base64 decoding
                decoded = base64.b64decode(transaction)
                return json.loads(decoded)
        except Exception as e:
            raise ValueError(f"Invalid transaction format: {str(e)}")
    
    def _extract_sender(self, tx_data: Dict[str, Any]) -> str:
        """Extract sender address from transaction data"""
        # Implementation depends on Solana transaction structure
        # This is a simplified example
        if "message" in tx_data and "accountKeys" in tx_data["message"]:
            return tx_data["message"]["accountKeys"][0]
        return "unknown"
    
    def _determine_labels(self, score: float, detection_results) -> List[str]:
        """Determine attack labels based on score and patterns"""
        labels = []
        
        # Check for specific patterns indicating dusting
        has_dust_value = any(
            r.detector_name == "value_threshold" and r.detected 
            for r in detection_results
        )
        
        has_high_frequency = any(
            r.detector_name == "frequency" and r.score > 0.8
            for r in detection_results
        )
        
        # Label as dusting if score and patterns match
        if score >= self.dusting_threshold and has_dust_value:
            labels.append("dusting")
            
        # Check for address poisoning patterns (similarity in addresses)
        has_similar_address = any(
            "similar_address" in r.reasons for r in detection_results
        )
        
        # Label as poisoning if score and patterns match
        if score >= self.poisoning_threshold and has_similar_address:
            labels.append("poisoning")
            
        # Default suspicious label if score is high but no specific attack identified
        if score > 0.6 and not labels:
            labels.append("suspicious")
            
        return labels
    
    async def _store_result(self, db, tx_data, score, labels, slot):
        """Store analysis result in database"""
        # Implementation depends on specific database schema
        pass