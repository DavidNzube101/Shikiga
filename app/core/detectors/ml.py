"""
Shikiga - Machine Learning Anomaly Detector

Implements machine learning-based anomaly detection for
identifying suspicious transactions patterns that may not be
caught by simpler heuristic approaches.
"""
import numpy as np
from typing import Dict, Any, List, Optional
import pickle
import os
from datetime import datetime

from app.core.detectors.base_detector import BaseDetector, DetectionResult

class AnomalyDetector(BaseDetector):
    """
    Uses machine learning models to detect anomalous transactions
    """
    
    def __init__(self, model_path: str = None):
        """
        Initialize with pre-trained model
        
        Args:
            model_path: Path to the trained model file (pickle format)
        """
        super().__init__("anomaly")
        self.model = self._load_model(model_path)
        
    def _load_model(self, model_path):
        """Load the pre-trained anomaly detection model"""
        if model_path and os.path.exists(model_path):
            try:
                with open(model_path, 'rb') as f:
                    return pickle.load(f)
            except Exception as e:
                print(f"Error loading model: {e}")
        
        # Return a simple fallback model if loading fails
        # In production, you'd want to handle this more gracefully
        return SimpleFallbackModel()
    
    async def detect(
        self, 
        transaction_data: Dict[str, Any], 
        slot: Optional[int] = None
    ) -> DetectionResult:
        """
        Apply ML model to detect anomalous transactions
        """
        try:
            # Extract features from transaction data
            features = self._extract_features(transaction_data, slot)
            
            # Make prediction
            if self.model:
                score = self.model.predict_proba([features])[0]
                
                if score > 0.7:  # High anomaly score
                    return DetectionResult(
                        detector_name=self.name,
                        detected=True,
                        score=float(score),
                        reasons=["ml_anomaly_detected"]
                    )
            
            return DetectionResult(
                detector_name=self.name,
                detected=False,
                score=0.0,
                reasons=[]
            )
            
        except Exception as e:
            # Log the error and return a safe default
            print(f"Error in anomaly detection: {e}")
            return DetectionResult(
                detector_name=self.name,
                detected=False,
                score=0.0,
                reasons=[]
            )
    
    def _extract_features(
        self, 
        transaction_data: Dict[str, Any],
        slot: Optional[int]
    ) -> List[float]:
        """
        Extract numerical features from transaction data for ML model
        
        This method converts raw transaction data into a feature vector
        that the ML model expects.
        """
        features = []
        
        # Feature 1: Transaction value in SOL
        value = self._get_transaction_value(transaction_data)
        features.append(value)
        
        # Feature 2: Number of accounts involved
        num_accounts = 0
        try:
            if "message" in transaction_data and "accountKeys" in transaction_data["message"]:
                num_accounts = len(transaction_data["message"]["accountKeys"])
        except Exception:
            pass
        features.append(num_accounts)
        
        # Feature 3: Number of instructions
        num_instructions = 0
        try:
            if "message" in transaction_data and "instructions" in transaction_data["message"]:
                num_instructions = len(transaction_data["message"]["instructions"])
        except Exception:
            pass
        features.append(num_instructions)
        
        # Feature 4: Time of day (0-23)
        hour = datetime.now().hour
        features.append(hour)
        
        # Feature 5: Has memo
        has_memo = 0
        memo = self._extract_memo(transaction_data)
        if memo:
            has_memo = 1
        features.append(has_memo)
        
        # Additional features can be added here
        
        return features
    
    def _extract_memo(self, transaction_data: Dict[str, Any]) -> Optional[str]:
        """Extract memo field from transaction data"""
        try:
            if "message" in transaction_data and "instructions" in transaction_data["message"]:
                for instruction in transaction_data["message"]["instructions"]:
                    # Check if this is a memo program instruction
                    program_id = instruction.get("programId")
                    if program_id == "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr":
                        return instruction.get("data", "")
        except Exception:
            pass
        return None


class SimpleFallbackModel:
    """
    A simple fallback model for when the ML model cannot be loaded
    
    This serves as a placeholder that implements the same interface
    as scikit-learn models but uses simple heuristics.
    """
    
    def predict_proba(self, features):
        """
        Predict anomaly probability based on simple rules
        
        Args:
            features: List of feature vectors
            
        Returns:
            List of anomaly scores
        """
        results = []
        
        for feature_vector in features:
            if len(feature_vector) >= 2:
                # If value is very low (dust) and there are many accounts
                value = feature_vector[0]
                num_accounts = feature_vector[1]
                
                if value < 0.001 and num_accounts > 3:
                    results.append(0.85)  # High anomaly score
                elif value < 0.01:
                    results.append(0.6)   # Moderate anomaly score
                else:
                    results.append(0.2)   # Low anomaly score
            else:
                results.append(0.0)
        
        return np.array(results)