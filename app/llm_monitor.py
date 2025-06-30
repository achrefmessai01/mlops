"""
LLM Monitoring System - Replace Langfuse functionality
Tracks API calls, costs, performance, and provides observability
"""

import time
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
import psycopg2
from contextlib import contextmanager
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class LLMRequest:
    """Data structure for LLM request tracking"""
    id: str
    timestamp: datetime
    user_id: Optional[str]
    model: str
    provider: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    cost_input: float
    cost_output: float
    total_cost: float
    latency_ms: int
    request_text: str
    response_text: str
    endpoint: str
    status: str = "success"
    error_message: Optional[str] = None

class LLMMonitor:
    """Simple LLM monitoring system to replace Langfuse"""
    
    # Token pricing per 1M tokens (update these with current prices)
    PRICING = {
        "gpt-4o-mini": {"input": 0.15, "output": 0.60},  # $0.15/$0.60 per 1M tokens
        "gpt-4o": {"input": 2.50, "output": 10.00},
        "gpt-3.5-turbo": {"input": 0.50, "output": 1.50},
        "claude-3-haiku": {"input": 0.25, "output": 1.25},
        "claude-3-sonnet": {"input": 3.00, "output": 15.00},
    }
    
    def __init__(self):
        self.db_config = {
            "host": os.getenv("POSTGRES_HOST", "localhost"),
            "port": os.getenv("POSTGRES_PORT", "5432"),
            "database": os.getenv("POSTGRES_DB", "mlops"),
            "user": os.getenv("POSTGRES_USER", "mlops"),
            "password": os.getenv("POSTGRES_PASSWORD", "mlops123"),
        }
        self._ensure_tables_exist()
    
    def _ensure_tables_exist(self):
        """Create LLM monitoring tables if they don't exist"""
        create_tables_sql = """
        CREATE TABLE IF NOT EXISTS llm_requests (
            id VARCHAR(255) PRIMARY KEY,
            timestamp TIMESTAMP NOT NULL,
            user_id VARCHAR(255),
            model VARCHAR(100) NOT NULL,
            provider VARCHAR(50) NOT NULL,
            prompt_tokens INTEGER NOT NULL,
            completion_tokens INTEGER NOT NULL,
            total_tokens INTEGER NOT NULL,
            cost_input DECIMAL(10,6) NOT NULL,
            cost_output DECIMAL(10,6) NOT NULL,
            total_cost DECIMAL(10,6) NOT NULL,
            latency_ms INTEGER NOT NULL,
            request_text TEXT,
            response_text TEXT,
            endpoint VARCHAR(255),
            status VARCHAR(50) DEFAULT 'success',
            error_message TEXT
        );
        
        CREATE INDEX IF NOT EXISTS idx_llm_requests_timestamp ON llm_requests(timestamp);
        CREATE INDEX IF NOT EXISTS idx_llm_requests_model ON llm_requests(model);
        CREATE INDEX IF NOT EXISTS idx_llm_requests_user_id ON llm_requests(user_id);
        """
        
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(create_tables_sql)
                conn.commit()
            logger.info("LLM monitoring tables created/verified")
        except Exception as e:
            logger.error(f"Failed to create monitoring tables: {e}")
    
    @contextmanager
    def _get_db_connection(self):
        """Database connection context manager"""
        conn = None
        try:
            conn = psycopg2.connect(**self.db_config)
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def calculate_cost(self, model: str, prompt_tokens: int, completion_tokens: int) -> tuple[float, float, float]:
        """Calculate costs for LLM usage"""
        pricing = self.PRICING.get(model, {"input": 1.0, "output": 2.0})  # Default fallback
        
        cost_input = (prompt_tokens / 1_000_000) * pricing["input"]
        cost_output = (completion_tokens / 1_000_000) * pricing["output"]
        total_cost = cost_input + cost_output
        
        return cost_input, cost_output, total_cost
    
    def log_request(self, request: LLMRequest):
        """Store LLM request in database"""
        insert_sql = """
        INSERT INTO llm_requests (
            id, timestamp, user_id, model, provider, prompt_tokens, completion_tokens,
            total_tokens, cost_input, cost_output, total_cost, latency_ms,
            request_text, response_text, endpoint, status, error_message
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
        """
        
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(insert_sql, (
                        request.id, request.timestamp, request.user_id, request.model,
                        request.provider, request.prompt_tokens, request.completion_tokens,
                        request.total_tokens, request.cost_input, request.cost_output,
                        request.total_cost, request.latency_ms, request.request_text,
                        request.response_text, request.endpoint, request.status,
                        request.error_message
                    ))
                conn.commit()
            
            # Also log to file for immediate visibility
            log_entry = {
                "timestamp": request.timestamp.isoformat(),
                "model": request.model,
                "tokens": request.total_tokens,
                "cost": request.total_cost,
                "latency_ms": request.latency_ms,
                "status": request.status
            }
            logger.info(f"LLM Request: {json.dumps(log_entry)}")
            
        except Exception as e:
            logger.error(f"Failed to log LLM request: {e}")
    
    def get_usage_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Get usage statistics for the last N hours"""
        query = """
        SELECT 
            COUNT(*) as total_requests,
            SUM(total_tokens) as total_tokens,
            SUM(total_cost) as total_cost,
            AVG(latency_ms) as avg_latency,
            model,
            COUNT(CASE WHEN status != 'success' THEN 1 END) as error_count
        FROM llm_requests 
        WHERE timestamp > NOW() - INTERVAL '%s hours'
        GROUP BY model
        ORDER BY total_cost DESC
        """
        
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(query, (hours,))
                    results = cursor.fetchall()
                    
                    stats = {
                        "period_hours": hours,
                        "models": []
                    }
                    
                    total_cost = 0
                    total_requests = 0
                    
                    for row in results:
                        model_stats = {
                            "model": row[4],
                            "requests": row[0],
                            "tokens": row[1] or 0,
                            "cost": float(row[2] or 0),
                            "avg_latency_ms": float(row[3] or 0),
                            "error_count": row[5] or 0
                        }
                        stats["models"].append(model_stats)
                        total_cost += model_stats["cost"]
                        total_requests += model_stats["requests"]
                    
                    stats["total_cost"] = total_cost
                    stats["total_requests"] = total_requests
                    
                    return stats
                    
        except Exception as e:
            logger.error(f"Failed to get usage stats: {e}")
            return {"error": str(e)}

# Global monitor instance
llm_monitor = LLMMonitor()

def track_llm_call(func):
    """Decorator to automatically track LLM API calls"""
    def wrapper(*args, **kwargs):
        start_time = time.time()
        request_id = f"req_{int(time.time() * 1000000)}"
        
        try:
            # Execute the LLM call
            result = func(*args, **kwargs)
            
            # Extract information from result (adapt based on your API response structure)
            latency_ms = int((time.time() - start_time) * 1000)
            
            # You'll need to adapt this based on your actual API response structure
            model = kwargs.get('model', 'unknown')
            prompt_tokens = getattr(result, 'usage', {}).get('prompt_tokens', 0)
            completion_tokens = getattr(result, 'usage', {}).get('completion_tokens', 0)
            total_tokens = prompt_tokens + completion_tokens
            
            cost_input, cost_output, total_cost = llm_monitor.calculate_cost(
                model, prompt_tokens, completion_tokens
            )
            
            # Create request record
            request = LLMRequest(
                id=request_id,
                timestamp=datetime.now(),
                user_id=kwargs.get('user_id'),
                model=model,
                provider="openai",  # or extract from model name
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                cost_input=cost_input,
                cost_output=cost_output,
                total_cost=total_cost,
                latency_ms=latency_ms,
                request_text=str(kwargs.get('messages', '')),
                response_text=str(result),
                endpoint=func.__name__,
                status="success"
            )
            
            llm_monitor.log_request(request)
            return result
            
        except Exception as e:
            latency_ms = int((time.time() - start_time) * 1000)
            
            # Log failed request
            request = LLMRequest(
                id=request_id,
                timestamp=datetime.now(),
                user_id=kwargs.get('user_id'),
                model=kwargs.get('model', 'unknown'),
                provider="openai",
                prompt_tokens=0,
                completion_tokens=0,
                total_tokens=0,
                cost_input=0.0,
                cost_output=0.0,
                total_cost=0.0,
                latency_ms=latency_ms,
                request_text=str(kwargs.get('messages', '')),
                response_text="",
                endpoint=func.__name__,
                status="error",
                error_message=str(e)
            )
            
            llm_monitor.log_request(request)
            raise
    
    return wrapper
