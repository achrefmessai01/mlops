"""
Scheduled LLM Judge Analysis Service
Runs periodic analysis of conversation data without Langfuse
"""
import asyncio
import schedule
import time
import logging
import os
from datetime import datetime
from simple_judge_system import SimpleJudgeSystem
import json

# Configuration
ANALYSIS_INTERVAL = int(os.getenv('JUDGE_ANALYSIS_INTERVAL', 3600))  # 1 heure par défaut
JUDGE_MODEL = os.getenv('JUDGE_MODEL', 'gpt-4o-mini')
ANALYSIS_HOURS_BACK = int(os.getenv('JUDGE_AUTO_ANALYSIS_HOURS', 24))

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class JudgeScheduler:
    def __init__(self):
        self.judge_system = None
        self.initialize_services()
    
    def initialize_services(self):
        """Initialize Simple Judge System"""
        try:
            # Initialize our simple judge system
            self.judge_system = SimpleJudgeSystem()
            logger.info("✅ Simple Judge System initialized successfully")
            
            # Verify OpenAI API key is available
            openai_key = os.getenv("OPENAI_API_KEY")
            if not openai_key:
                logger.warning("⚠️ OpenAI API key not found - some analysis features may be limited")
                
        except Exception as e:
            logger.error(f"❌ Failed to initialize Judge Scheduler: {e}")
    
    async def run_scheduled_analysis(self):
        """Run the scheduled analysis"""
        try:
            if not self.judge_system:
                logger.error("Judge system not initialized")
                return
            
            logger.info(f"🔍 Starting scheduled analysis for last {ANALYSIS_HOURS_BACK} hours...")
            
            # Run analysis on recent conversations
            analysis_results = await self.judge_system.analyze_recent_conversations(
                hours_back=ANALYSIS_HOURS_BACK
            )
            
            # Get system health analysis
            system_health = await self.judge_system.analyze_system_health(
                hours_back=ANALYSIS_HOURS_BACK
            )
            
            # Get risk dashboard
            risk_dashboard = await self.judge_system.get_risk_dashboard(
                hours_back=ANALYSIS_HOURS_BACK
            )
            
            # Compile comprehensive insights
            insights = {
                "timestamp": datetime.now().isoformat(),
                "analysis_period_hours": ANALYSIS_HOURS_BACK,
                "conversation_analysis": analysis_results,
                "system_health": system_health,
                "risk_dashboard": risk_dashboard,
                "summary": {
                    "total_conversations": analysis_results.get("conversations_analyzed", 0),
                    "high_risk_conversations": analysis_results.get("high_risk_count", 0),
                    "unique_users": system_health.get("unique_users", 0),
                    "critical_users": risk_dashboard.get("risk_summary", {}).get("critical_users", 0),
                    "high_risk_users": risk_dashboard.get("risk_summary", {}).get("high_risk_users", 0)
                }
            }
            
            # Save results
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            analysis_file = f"/app/judge_analysis/analysis_{timestamp}.json"
            
            os.makedirs("/app/judge_analysis", exist_ok=True)
            with open(analysis_file, 'w') as f:
                json.dump(insights, f, indent=2, default=str)
            
            # Log summary
            summary = insights["summary"]
            logger.info(f"📊 Analysis completed:")
            logger.info(f"   - Conversations analyzed: {summary['total_conversations']}")
            logger.info(f"   - High risk conversations: {summary['high_risk_conversations']}")
            logger.info(f"   - Unique users: {summary['unique_users']}")
            logger.info(f"   - Critical users: {summary['critical_users']}")
            logger.info(f"   - High risk users: {summary['high_risk_users']}")
            
            # Send alerts if needed
            if summary["critical_users"] > 0 or summary["high_risk_users"] > 0:
                await self.send_alert(insights)
            
            logger.info(f"✅ Analysis saved to {analysis_file}")
            
        except Exception as e:
            logger.error(f"❌ Scheduled analysis failed: {e}")
    
    async def send_alert(self, insights):
        """Send alert for high-risk findings"""
        try:
            summary = insights.get('summary', {})
            critical_users = summary.get('critical_users', 0)
            high_risk_users = summary.get('high_risk_users', 0)
            high_risk_conversations = summary.get('high_risk_conversations', 0)
            
            alert_message = f"""
🚨 MLOPS SECURITY ALERT
            
High-risk AI usage detected:
• {critical_users} CRITICAL risk users
• {high_risk_users} HIGH risk users
• {high_risk_conversations} HIGH risk conversations

Immediate action required. Check dashboard for details.
            """
            
            logger.warning(alert_message)
            
            # Here you could integrate with:
            # - Email notifications
            # - Slack/Teams webhooks
            # - SMS alerts
            # - Push notifications
            
        except Exception as e:
            logger.error(f"Failed to send alert: {e}")
    
    def run_sync_analysis(self):
        """Synchronous wrapper for async analysis"""
        try:
            asyncio.run(self.run_scheduled_analysis())
        except Exception as e:
            logger.error(f"Sync analysis wrapper failed: {e}")

def main():
    """Main scheduler loop"""
    logger.info("🚀 Starting Judge Scheduler Service...")
    
    scheduler = JudgeScheduler()
    
    # Schedule analysis every hour
    schedule.every().hour.do(scheduler.run_sync_analysis)
    
    # Also run immediately on startup
    logger.info("Running initial analysis...")
    scheduler.run_sync_analysis()
    
    # Main loop
    logger.info(f"📅 Scheduled to run every {ANALYSIS_INTERVAL} seconds")
    while True:
        schedule.run_pending()
        time.sleep(60)  # Check every minute

if __name__ == "__main__":
    main()