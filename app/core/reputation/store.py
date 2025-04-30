"""
Shikiga - Reputation Store

Manages a lightweight cache for tracking sender reputation
and transaction frequency over time.
"""
import time
from typing import Dict, List, Optional
import aioredis
from datetime import datetime, timedelta

class ReputationStore:
    """
    Manages reputation scores and transaction history for addresses
    
    Uses Redis for efficient storage and retrieval of reputation data.
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        """
        Initialize the reputation store with Redis connection
        
        Args:
            redis_url: URL for the Redis instance
        """
        self.redis = None
        self.redis_url = redis_url
        
        # Default reputation score for unknown addresses
        self.default_reputation = 0.5
        
        # Key expiration time (in seconds)
        self.expiration = 60 * 60 * 24 * 30  # 30 days
    
    async def initialize(self):
        """Initialize Redis connection pool"""
        if self.redis is None:
            self.redis = await aioredis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True
            )
    
    async def get_score(self, address: str) -> float:
        """
        Get the reputation score for an address
        
        Args:
            address: Wallet address to check
            
        Returns:
            Reputation score (0-1, higher is better)
        """
        await self.initialize()
        
        try:
            score = await self.redis.get(f"rep:{address}")
            if score is not None:
                return float(score)
            return self.default_reputation
        except Exception:
            return self.default_reputation
    
    async def update_score(self, address: str, score: float) -> bool:
        """
        Update the reputation score for an address
        
        Args:
            address: Wallet address to update
            score: New reputation score (0-1)
            
        Returns:
            True if update was successful
        """
        await self.initialize()
        
        try:
            # Ensure score is within valid range
            score = max(0.0, min(1.0, score))
            
            # Set score with expiration
            await self.redis.set(
                f"rep:{address}", 
                str(score),
                ex=self.expiration
            )
            return True
        except Exception:
            return False
    
    async def record_transaction(
        self, 
        address: str, 
        slot: Optional[int] = None
    ) -> bool:
        """
        Record a transaction for frequency tracking
        
        Args:
            address: Address that initiated the transaction
            slot: Block slot where transaction was included
            
        Returns:
            True if recording was successful
        """
        await self.initialize()
        
        try:
            # Get current timestamp
            timestamp = int(time.time())
            
            # Record in sorted set with timestamp as score
            # This enables efficient range queries by time
            await self.redis.zadd(
                f"tx_history:{address}",
                {f"{timestamp}:{slot or 0}": timestamp}
            )
            
            # Set expiration on the key
            await self.redis.expire(f"tx_history:{address}", self.expiration)
            
            return True
        except Exception:
            return False
    
    async def get_recent_tx_count(
        self, 
        address: str, 
        time_window: int = 3600
    ) -> int:
        """
        Get count of recent transactions from an address
        
        Args:
            address: Address to check
            time_window: Time window in seconds (default: 1 hour)
            
        Returns:
            Number of transactions in the specified time window
        """
        await self.initialize()
        
        try:
            # Calculate minimum timestamp
            now = int(time.time())
            min_time = now - time_window
            
            # Count transactions in time window
            count = await self.redis.zcount(
                f"tx_history:{address}",
                min_time,
                "+inf"
            )
            
            return count
        except Exception:
            return 0
    
    async def get_transaction_history(
        self, 
        address: str, 
        limit: int = 100
    ) -> List[Dict]:
        """
        Get recent transaction history for an address
        
        Args:
            address: Address to check
            limit: Maximum number of transactions to return
            
        Returns:
            List of transaction records ordered by recency
        """
        await self.initialize()
        
        try:
            # Get recent transactions (highest scores first)
            entries = await self.redis.zrevrange(
                f"tx_history:{address}", 
                0, 
                limit - 1,
                withscores=True
            )
            
            result = []
            for entry_id, timestamp in entries:
                # Parse timestamp and slot from entry
                parts = entry_id.split(":")
                if len(parts) == 2:
                    slot = int(parts[1])
                    dt = datetime.fromtimestamp(timestamp)
                    
                    result.append({
                        "timestamp": dt.isoformat(),
                        "slot": slot
                    })
            
            return result
        except Exception:
            return []