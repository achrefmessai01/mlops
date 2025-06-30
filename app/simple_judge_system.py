"""
Simple Judge System - Works without Langfuse
Stores conversation data locally and performs risk analysis
"""

import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import psycopg2
from contextlib import contextmanager
import os
from llm_monitor import track_llm_call, llm_monitor
import openai

logger = logging.getLogger(__name__)

class SimpleJudgeSystem:
    """Judge system that works without Langfuse"""
    
    def __init__(self):
        self.db_config = {
            "host": os.getenv("POSTGRES_HOST", "localhost"),
            "port": os.getenv("POSTGRES_PORT", "5432"),
            "database": os.getenv("POSTGRES_DB", "mlops"),
            "user": os.getenv("POSTGRES_USER", "mlops"),
            "password": os.getenv("POSTGRES_PASSWORD", "mlops123"),
        }
        self.client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self._ensure_tables_exist()
    
    def _ensure_tables_exist(self):
        """Create judge system tables"""
        create_tables_sql = """
        CREATE TABLE IF NOT EXISTS conversations (
            id SERIAL PRIMARY KEY,
            session_id VARCHAR(255),
            user_id VARCHAR(255),
            timestamp TIMESTAMP DEFAULT NOW(),
            user_message TEXT,
            assistant_message TEXT,
            model VARCHAR(100),
            risk_score INTEGER DEFAULT 0,
            risk_analysis TEXT,
            analyzed BOOLEAN DEFAULT FALSE
        );
        
        CREATE TABLE IF NOT EXISTS judge_analyses (
            id SERIAL PRIMARY KEY,
            conversation_id INTEGER REFERENCES conversations(id),
            analysis_timestamp TIMESTAMP DEFAULT NOW(),
            risk_score INTEGER,
            risk_category VARCHAR(100),
            reasoning TEXT,
            judge_model VARCHAR(100)
        );
        
        CREATE INDEX IF NOT EXISTS idx_conversations_timestamp ON conversations(timestamp);
        CREATE INDEX IF NOT EXISTS idx_conversations_analyzed ON conversations(analyzed);
        """
        
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(create_tables_sql)
                conn.commit()
            logger.info("Judge system tables created/verified")
        except Exception as e:
            logger.error(f"Failed to create judge tables: {e}")
    
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
    
    def store_conversation(self, session_id: str, user_id: str, user_message: str, 
                          assistant_message: str, model: str) -> int:
        """Store a conversation for later analysis"""
        insert_sql = """
        INSERT INTO conversations (session_id, user_id, user_message, assistant_message, model)
        VALUES (%s, %s, %s, %s, %s) RETURNING id
        """
        
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(insert_sql, (session_id, user_id, user_message, assistant_message, model))
                    conversation_id = cursor.fetchone()[0]
                conn.commit()
            
            logger.info(f"Stored conversation {conversation_id}")
            return conversation_id
            
        except Exception as e:
            logger.error(f"Failed to store conversation: {e}")
            return -1
    
    @track_llm_call
    def analyze_conversation(self, conversation_id: int) -> Dict[str, Any]:
        """Analyze a single conversation for risks"""
        
        # Get conversation data
        get_conversation_sql = """
        SELECT user_message, assistant_message, model FROM conversations WHERE id = %s
        """
        
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(get_conversation_sql, (conversation_id,))
                    result = cursor.fetchone()
                    
                    if not result:
                        return {"error": "Conversation not found"}
                    
                    user_message, assistant_message, model = result
            
            # Analyze with judge model
            judge_prompt = f"""
            Analyze this conversation for security risks, harmful content, or policy violations.
            Rate the risk level from 1-10 and provide reasoning.
            
            User: {user_message}
            Assistant: {assistant_message}
            Model: {model}
            
            Respond in JSON format:
            {{
                "risk_score": <1-10>,
                "risk_category": "<category>",
                "reasoning": "<detailed explanation>",
                "threats_detected": ["<list of threats>"]
            }}
            """
            
            response = self.client.chat.completions.create(
                model=os.getenv("JUDGE_MODEL", "gpt-4o-mini"),
                messages=[{"role": "user", "content": judge_prompt}],
                temperature=0.1,
                user_id=f"judge_analysis_{conversation_id}"
            )
            
            analysis_text = response.choices[0].message.content
            
            try:
                analysis = json.loads(analysis_text)
            except json.JSONDecodeError:
                analysis = {
                    "risk_score": 5,
                    "risk_category": "parse_error",
                    "reasoning": f"Failed to parse judge response: {analysis_text}",
                    "threats_detected": []
                }
            
            # Store analysis
            self._store_analysis(conversation_id, analysis)
            
            # Update conversation as analyzed
            update_sql = """
            UPDATE conversations 
            SET analyzed = TRUE, risk_score = %s, risk_analysis = %s 
            WHERE id = %s
            """
            
            with self._get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(update_sql, (
                        analysis["risk_score"], 
                        analysis["reasoning"], 
                        conversation_id
                    ))
                conn.commit()
            
            return analysis
            
        except Exception as e:
            logger.error(f"Failed to analyze conversation {conversation_id}: {e}")
            return {"error": str(e)}
    
    def _store_analysis(self, conversation_id: int, analysis: Dict[str, Any]):
        """Store judge analysis results"""
        insert_sql = """
        INSERT INTO judge_analyses (conversation_id, risk_score, risk_category, reasoning, judge_model)
        VALUES (%s, %s, %s, %s, %s)
        """
        
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(insert_sql, (
                        conversation_id,
                        analysis.get("risk_score", 0),
                        analysis.get("risk_category", "unknown"),
                        analysis.get("reasoning", ""),
                        os.getenv("JUDGE_MODEL", "gpt-4o-mini")
                    ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to store analysis: {e}")
    
    def get_unanalyzed_conversations(self, hours_back: int = 24) -> List[int]:
        """Get conversations that need analysis"""
        query = """
        SELECT id FROM conversations 
        WHERE analyzed = FALSE 
        AND timestamp > NOW() - INTERVAL '%s hours'
        ORDER BY timestamp DESC
        LIMIT 100
        """
        
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(query, (hours_back,))
                    return [row[0] for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get unanalyzed conversations: {e}")
            return []
    
    def get_risk_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get risk analysis summary"""
        query = """
        SELECT 
            COUNT(*) as total_conversations,
            AVG(risk_score) as avg_risk_score,
            COUNT(CASE WHEN risk_score >= 7 THEN 1 END) as high_risk_count,
            COUNT(CASE WHEN risk_score >= 5 THEN 1 END) as medium_risk_count,
            COUNT(CASE WHEN analyzed = TRUE THEN 1 END) as analyzed_count
        FROM conversations 
        WHERE timestamp > NOW() - INTERVAL '%s hours'
        """
        
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(query, (hours,))
                    result = cursor.fetchone()
                    
                    if result:
                        return {
                            "period_hours": hours,
                            "total_conversations": result[0],
                            "avg_risk_score": float(result[1] or 0),
                            "high_risk_count": result[2],
                            "medium_risk_count": result[3],
                            "analyzed_count": result[4],
                            "analysis_coverage": f"{(result[4]/max(result[0], 1)*100):.1f}%"
                        }
                    else:
                        return {"error": "No data found"}
                        
        except Exception as e:
            logger.error(f"Failed to get risk summary: {e}")
            return {"error": str(e)}

    async def analyze_recent_conversations(self, hours_back: int = 24) -> Dict[str, Any]:
        """Analyze recent conversations and return summary"""
        try:
            # Get unanalyzed conversations
            conversation_ids = self.get_unanalyzed_conversations(hours_back)
            
            if not conversation_ids:
                return {
                    "conversations_analyzed": 0,
                    "high_risk_count": 0,
                    "average_risk_score": 0,
                    "risk_categories": {},
                    "analyses": []
                }
            
            analyses = []
            high_risk_count = 0
            total_risk_score = 0
            risk_categories = {}
            
            # Analyze each conversation
            for conv_id in conversation_ids:
                analysis = await self.analyze_conversation(conv_id)
                if analysis and "risk_score" in analysis:
                    analyses.append({
                        "conversation_id": conv_id,
                        "risk_score": analysis["risk_score"],
                        "risk_category": analysis.get("risk_category", "unknown"),
                        "reasoning": analysis.get("reasoning", "")
                    })
                    
                    if analysis["risk_score"] >= 7:
                        high_risk_count += 1
                    
                    total_risk_score += analysis["risk_score"]
                    
                    category = analysis.get("risk_category", "unknown")
                    risk_categories[category] = risk_categories.get(category, 0) + 1
            
            return {
                "conversations_analyzed": len(analyses),
                "high_risk_count": high_risk_count,
                "average_risk_score": total_risk_score / max(len(analyses), 1),
                "risk_categories": risk_categories,
                "analyses": analyses[:10]  # Return top 10 for display
            }
            
        except Exception as e:
            logger.error(f"Failed to analyze recent conversations: {e}")
            return {"error": str(e)}
    
    async def analyze_user_conversations(self, user_id: str, hours_back: int = 24) -> Dict[str, Any]:
        """Analyze conversations for a specific user"""
        query = """
        SELECT id, user_message, assistant_message, model, risk_score, risk_analysis
        FROM conversations 
        WHERE user_id = %s AND timestamp > NOW() - INTERVAL '%s hours'
        ORDER BY timestamp DESC
        """
        
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(query, (user_id, hours_back))
                    conversations = cursor.fetchall()
            
            if not conversations:
                return {
                    "user_id": user_id,
                    "conversations_count": 0,
                    "average_risk_score": 0,
                    "conversations": []
                }
            
            total_risk = 0
            analyzed_conversations = []
            
            for conv in conversations:
                conv_id, user_msg, assistant_msg, model, risk_score, risk_analysis = conv
                
                # If not analyzed yet, analyze now
                if risk_score == 0 or not risk_analysis:
                    analysis = await self.analyze_conversation(conv_id)
                    risk_score = analysis.get("risk_score", 0) if analysis else 0
                    risk_analysis = analysis.get("reasoning", "") if analysis else ""
                
                total_risk += risk_score
                analyzed_conversations.append({
                    "conversation_id": conv_id,
                    "user_message": user_msg[:200] + "..." if len(user_msg) > 200 else user_msg,
                    "risk_score": risk_score,
                    "risk_analysis": risk_analysis,
                    "model": model
                })
            
            return {
                "user_id": user_id,
                "conversations_count": len(conversations),
                "average_risk_score": total_risk / len(conversations),
                "conversations": analyzed_conversations
            }
            
        except Exception as e:
            logger.error(f"Failed to analyze user conversations: {e}")
            return {"error": str(e)}
    
    async def analyze_system_health(self, hours_back: int = 24) -> Dict[str, Any]:
        """Analyze overall system health and patterns"""
        query = """
        SELECT 
            COUNT(*) as total_conversations,
            COUNT(DISTINCT user_id) as unique_users,
            AVG(risk_score) as avg_risk_score,
            COUNT(CASE WHEN risk_score >= 7 THEN 1 END) as high_risk_conversations,
            COUNT(CASE WHEN risk_score >= 5 THEN 1 END) as medium_risk_conversations,
            model,
            COUNT(*) as model_usage
        FROM conversations 
        WHERE timestamp > NOW() - INTERVAL '%s hours'
        GROUP BY model
        ORDER BY model_usage DESC
        """
        
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cursor:
                    # Get overall stats
                    cursor.execute("""
                        SELECT 
                            COUNT(*) as total_conversations,
                            COUNT(DISTINCT user_id) as unique_users,
                            AVG(risk_score) as avg_risk_score,
                            COUNT(CASE WHEN risk_score >= 7 THEN 1 END) as high_risk_conversations,
                            COUNT(CASE WHEN risk_score >= 5 THEN 1 END) as medium_risk_conversations
                        FROM conversations 
                        WHERE timestamp > NOW() - INTERVAL %s
                    """, (f"{hours_back} hours",))
                    
                    stats = cursor.fetchone()
                    
                    # Get model usage
                    cursor.execute("""
                        SELECT model, COUNT(*) as usage_count
                        FROM conversations 
                        WHERE timestamp > NOW() - INTERVAL %s
                        GROUP BY model
                        ORDER BY usage_count DESC
                    """, (f"{hours_back} hours",))
                    
                    model_usage = cursor.fetchall()
            
            return {
                "analysis_timestamp": datetime.now().isoformat(),
                "period_hours": hours_back,
                "total_conversations": stats[0] if stats else 0,
                "unique_users": stats[1] if stats else 0,
                "average_risk_score": float(stats[2] or 0) if stats else 0,
                "high_risk_conversations": stats[3] if stats else 0,
                "medium_risk_conversations": stats[4] if stats else 0,
                "model_usage": [{"model": model, "count": count} for model, count in model_usage],
                "security_concerns": [],  # Could add specific security pattern detection
                "performance_issues": []  # Could add performance analysis
            }
            
        except Exception as e:
            logger.error(f"Failed to analyze system health: {e}")
            return {"error": str(e)}
    
    async def get_risk_dashboard(self, hours_back: int = 24, risk_level: str = None) -> Dict[str, Any]:
        """Get comprehensive risk dashboard data"""
        try:
            # Get user risk analysis
            query = """
            SELECT 
                user_id,
                COUNT(*) as conversation_count,
                AVG(risk_score) as avg_risk_score,
                MAX(risk_score) as max_risk_score,
                COUNT(CASE WHEN risk_score >= 7 THEN 1 END) as high_risk_count
            FROM conversations 
            WHERE timestamp > NOW() - INTERVAL %s
            GROUP BY user_id
            ORDER BY avg_risk_score DESC, conversation_count DESC
            """
            
            with self._get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(query, (f"{hours_back} hours",))
                    user_data = cursor.fetchall()
            
            users = []
            risk_summary = {"total_users": 0, "critical_users": 0, "high_risk_users": 0, 
                          "medium_risk_users": 0, "low_risk_users": 0}
            
            for user_id, conv_count, avg_risk, max_risk, high_risk_count in user_data:
                avg_risk = float(avg_risk or 0)
                max_risk = float(max_risk or 0)
                
                # Determine risk level
                if avg_risk >= 8:
                    user_risk_level = "CRITICAL"
                    risk_summary["critical_users"] += 1
                elif avg_risk >= 6:
                    user_risk_level = "HIGH"
                    risk_summary["high_risk_users"] += 1
                elif avg_risk >= 4:
                    user_risk_level = "MEDIUM"
                    risk_summary["medium_risk_users"] += 1
                else:
                    user_risk_level = "LOW"
                    risk_summary["low_risk_users"] += 1
                
                # Filter by risk level if specified
                if risk_level and user_risk_level != risk_level.upper():
                    continue
                
                users.append({
                    "user_id": user_id,
                    "conversation_count": conv_count,
                    "average_risk_score": avg_risk,
                    "max_risk_score": max_risk,
                    "high_risk_conversations": high_risk_count,
                    "risk_level": user_risk_level
                })
            
            risk_summary["total_users"] = len(user_data)
            
            # Get system health
            system_health = await self.analyze_system_health(hours_back)
            
            return {
                "risk_summary": risk_summary,
                "users": users[:50],  # Limit to top 50 users
                "system_alerts": {
                    "total_conversations": system_health.get("total_conversations", 0),
                    "unique_users": system_health.get("unique_users", 0),
                    "high_risk_conversations": system_health.get("high_risk_conversations", 0),
                    "security_concerns": system_health.get("security_concerns", []),
                    "performance_issues": system_health.get("performance_issues", [])
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get risk dashboard: {e}")
            return {"error": str(e)}

# Global judge system instance
judge_system = SimpleJudgeSystem()
