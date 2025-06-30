from fastapi import FastAPI, Request, Response, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, ConfigDict
import os
import requests
import logging
import time
from typing import List, Optional, Any
from dotenv import load_dotenv
import traceback
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
import re
import json
from datetime import datetime
import uuid

# Importer nos modules d'analyse
from security_analyzer import SecurityAnalyzer
from kpi_analyzer import KPIAnalyzer
from ai_analysis_agent import AIAnalysisAgent
from monitoring_dashboard import MonitoringDashboard
from llm_monitor import LLMMonitor, LLMRequest, track_llm_call
from simple_judge_system import SimpleJudgeSystem
import asyncio

# Initialize FastAPI
app = FastAPI(title="MLOps Monitoring Platform", description="Plateforme de monitoring et analyse des inférences IA")

# Load environment variables
load_dotenv()

# PROMETHEUS METRICS - COMPLETE DEFINITIONS
REQUEST_COUNT = Counter('mlops_requests_total', 'Total requests', ['method', 'endpoint', 'status'])
REQUEST_LATENCY = Histogram('mlops_request_duration_seconds', 'Request latency')
SECURITY_THREATS = Counter('mlops_security_threats_total', 'Security threats detected', ['risk_level'])
HIGH_RISK_USERS = Gauge('mlops_security_high_risk_users_total', 'Current high-risk users')
CRITICAL_THREATS = Gauge('mlops_security_critical_threats_total', 'Current critical threats')
AI_COSTS = Counter('mlops_ai_total_cost_usd', 'Total AI costs in USD')
JUDGE_ANALYSIS = Counter('mlops_judge_analysis_total', 'Judge analyses performed', ['type', 'status'])
JUDGE_LAST_ANALYSIS = Gauge('mlops_judge_last_analysis_timestamp', 'Last judge analysis timestamp')

# Additional metrics for your MLOps platform
INFERENCES_TOTAL = Counter('mlops_inferences_total', 'Total inferences', ['model', 'user_id'])
INFERENCE_LATENCY = Histogram('mlops_inference_latency_seconds', 'Inference latency', ['endpoint', 'model', 'user_ip'])
TOKEN_USAGE = Counter('mlops_tokens_total', 'Total tokens used', ['model', 'type'])
MODEL_ERRORS = Counter('mlops_model_errors_total', 'Model errors', ['model', 'error_type'])

# Additional metrics that were missing
PROMPT_LENGTH = Histogram('mlops_prompt_length_characters', 'Prompt length in characters', ['endpoint', 'model', 'user_ip'])
RESPONSE_LENGTH = Histogram('mlops_response_length_characters', 'Response length in characters', ['endpoint', 'model', 'user_ip'])

# Setup logger
logger = logging.getLogger(__name__)

# Initialize services
security_analyzer = None
kpi_analyzer = None
ai_analysis_agent = None
monitoring_dashboard = None
dashboard = None  # Alias for monitoring_dashboard
ai_agent = None   # Alias for ai_analysis_agent
judge_system = None

# Servir les fichiers statiques
app.mount("/static", StaticFiles(directory="static"), name="static")

# Load model API keys from .env file
load_dotenv(os.path.join(os.path.dirname(__file__), "model_api_keys.env"))

# Configure logging
logging.basicConfig(level=logging.INFO, filename='logs/inference.log', filemode='a', format='%(asctime)s %(message)s')

# Initialize monitoring systems
llm_monitor = LLMMonitor()
judge_system = SimpleJudgeSystem()

# API Keys
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

MODEL_NAMES = {
    "qwendeepseek": "deepseek/deepseek-r1-0528-qwen3-8b:free",
    "gemma3n": "google/gemma-3n-e4b-it:free",  
    "llama4": "meta-llama/llama-4-maverick:free",
    "mistral": "mistralai/mistral-small-3.2-24b-instruct:free",
    "gpt4": "gpt-4o-mini",  # OpenAI direct
    "gpt35": "gpt-3.5-turbo"  # OpenAI direct
}

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENAI_URL = "https://api.openai.com/v1/chat/completions"

class MessageContent(BaseModel):
    type: str  # 'text' or 'image_url'
    text: Optional[str] = None
    image_url: Optional[dict] = None

class Message(BaseModel):
    role: str  # 'user', 'system', etc.
    content: List[MessageContent]

class InferenceRequest(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    
    model_name: str
    messages: List[Message] = Field(..., description="List of chat messages, each with content (text and/or image_url)")

class InferenceResponse(BaseModel):
    result: str
    latency: float

def call_openrouter_api(model, messages, api_key=None, referer=None, title=None):
    if api_key is None:
        api_key = OPENROUTER_API_KEY
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    if referer:
        headers["HTTP-Referer"] = referer
    if title:
        headers["X-Title"] = title
    
    # Detect if any message contains an image
    multimodal = any(
        any(part.type == "image_url" for part in msg.content)
        for msg in messages
    )
    
    openai_messages = []
    for msg in messages:
        if multimodal:
            # Preserve content as a list of dicts for multimodal
            content = [part.dict() for part in msg.content]
        else:
            # Concatenate all text parts for text-only
            text_parts = [part.text for part in msg.content if part.type == "text" and part.text]
            content = "\n".join(text_parts)
        openai_messages.append({
            "role": msg.role,
            "content": content
        })
    
    data = {
        "model": model,
        "messages": openai_messages
    }
    
    logging.info(f"OpenRouter payload: {data}")
    
    try:
        response = requests.post(
            url=OPENROUTER_URL,
            headers=headers,
            json=data,
            timeout=60
        )
        response.raise_for_status()
        resp_json = response.json()
        if "choices" not in resp_json:
            logging.error(f"OpenRouter API unexpected response: {resp_json}")
            raise Exception(f"OpenRouter API did not return 'choices': {resp_json}")
        return resp_json["choices"][0]["message"]["content"]
    except requests.exceptions.HTTPError as e:
        try:
            error_detail = response.json()
        except Exception:
            error_detail = response.text
        logging.error(f"OpenRouter API error response: {error_detail}")
        raise Exception(f"{e} | OpenRouter response: {error_detail}")

def call_openai_api(model, messages):
    """Call OpenAI API directly"""
    if not OPENAI_API_KEY:
        raise Exception("OPENAI_API_KEY not configured")
    
    # Convert messages to OpenAI format
    openai_messages = []
    for msg in messages:
        # Concatenate all text parts
        text_parts = [part.text for part in msg.content if part.type == "text" and part.text]
        content = "\n".join(text_parts)
        openai_messages.append({
            "role": msg.role,
            "content": content
        })
    
    data = {
        "model": model,
        "messages": openai_messages,
        "temperature": 0.7,
        "max_tokens": 2000
    }
    
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }
    
    logging.info(f"OpenAI payload: {data}")
    
    try:
        response = requests.post(
            url=OPENAI_URL,
            headers=headers,
            json=data,
            timeout=60
        )
        response.raise_for_status()
        resp_json = response.json()
        
        if "choices" not in resp_json:
            logging.error(f"OpenAI API unexpected response: {resp_json}")
            raise Exception(f"OpenAI API did not return 'choices': {resp_json}")
        
        return resp_json["choices"][0]["message"]["content"]
        
    except requests.exceptions.HTTPError as e:
        try:
            error_detail = response.json()
        except Exception:
            error_detail = response.text
        logging.error(f"OpenAI API error response: {error_detail}")
        raise Exception(f"{e} | OpenAI response: {error_detail}")

# Utility functions that need to be defined before routes
def get_current_user_optional():
    """
    Optional dependency for getting current user - returns None if not available
    For now, returns None since we don't have authentication system
    """
    return None

def log_security_event(event_type: str, user_id: str, severity: str, details: dict):
    """
    Log security event for analysis
    """
    try:
        # Log to security analyzer if available
        if security_analyzer:
            security_analyzer.log_security_event(event_type, user_id, severity, details)
        
        # Also log to standard logging
        logging.warning(f"Security Event: {event_type} | User: {user_id} | Severity: {severity} | Details: {details}")
        
        # Update Prometheus metrics
        SECURITY_THREATS.labels(risk_level=severity).inc()
        
    except Exception as e:
        logging.error(f"Error logging security event: {e}")

@app.get("/metrics")
async def get_metrics():
    """Prometheus metrics endpoint"""
    try:
        # Update current metrics before serving
        if judge_system:
            # Update judge metrics
            JUDGE_LAST_ANALYSIS.set(time.time())
        
        # Generate and return metrics
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
    except Exception as e:
        logger.error(f"Error generating metrics: {e}")
        return Response("# Error generating metrics", media_type=CONTENT_TYPE_LATEST)

@app.post("/generate", response_model=InferenceResponse)
async def generate_text(request: Request, body: InferenceRequest):
    start_time = time.time()
    model_name = body.model_name.lower()
    endpoint = str(request.url.path)
    user_ip = str(request.client.host)
    prompt_text = " ".join(
        part.text for msg in body.messages for part in msg.content if part.type == "text" and part.text
    )
    
    # Analyse de sécurité du prompt
    if security_analyzer is not None:
        security_analysis = security_analyzer.analyze_prompt(prompt_text, user_ip)
        
        # Bloquer si risque critique
        if security_analysis["risk_level"] == "CRITICAL":
            logging.critical(f"BLOCKED_REQUEST: {security_analysis}")
            raise HTTPException(
                status_code=403, 
                detail={
                    "error": "Requête bloquée pour des raisons de sécurité",
                    "risk_level": security_analysis["risk_level"],
                    "threats": security_analysis["threats_detected"]
                }
            )
    else:
        # Default security analysis when analyzer is not available
        security_analysis = {
            "risk_level": "UNKNOWN",
            "threats_detected": [],
            "risk_score": 0.0,
            "recommendations": ["Security analyzer not initialized"]
        }

    # Prometheus metrics: count and observe
    INFERENCES_TOTAL.labels(model_name, user_ip).inc()
    prompt_len = len(prompt_text)
    PROMPT_LENGTH.labels("/generate", model_name, user_ip).observe(prompt_len)

    try:
        # Déterminer quel API utiliser
        if model_name in ["gpt4", "gpt35"]:
            result = call_openai_api(MODEL_NAMES[model_name], body.messages)
        else:
            result = call_openrouter_api(
                model=MODEL_NAMES[model_name],
                messages=body.messages
            )
    except Exception as e:
        tb = traceback.format_exc()
        logging.error(f"Model API call failed: {e}")
        logging.error(tb)
        raise HTTPException(status_code=500, detail={"error": str(e), "traceback": tb})

    latency = time.time() - start_time
    INFERENCE_LATENCY.labels("/generate", model_name, user_ip).observe(latency)
    RESPONSE_LENGTH.labels("/generate", model_name, user_ip).observe(len(result))
    
    # Structured log for analytics
    log_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
        "user": user_ip,
        "endpoint": endpoint,
        "model": model_name,
        "prompt": prompt_text,
        "prompt_length": prompt_len,
        "response": result,
        "response_length": len(result),
        "latency": latency,
        "security_analysis": security_analysis
    }
    
    logging.info(f"INFERENCE_LOG: {log_data}")
    
    # Traiter via le dashboard pour analyses KPI
    if dashboard:
        dashboard.log_inference(log_data)
    
    # Log the LLM request for observability and cost tracking
    try:
        # Generate unique request ID
        request_id = str(uuid.uuid4())
        
        # Estimate token usage (rough approximation)
        prompt_tokens = len(prompt_text.split()) * 1.3  # Rough token estimate
        completion_tokens = len(result.split()) * 1.3
        
        # Track the LLM call
        llm_request = LLMRequest(
            id=request_id,
            timestamp=datetime.now(),
            user_id=user_ip,  # Using IP as user_id for now
            model=model_name,
            provider="openrouter" if model_name not in ["gpt-4o-mini", "gpt-3.5-turbo"] else "openai",
            prompt_tokens=int(prompt_tokens),
            completion_tokens=int(completion_tokens),
            total_tokens=int(prompt_tokens + completion_tokens),
            cost_input=0.0,  # Will be calculated by the monitor
            cost_output=0.0,  # Will be calculated by the monitor
            total_cost=0.0,  # Will be calculated by the monitor
            latency_ms=int(latency * 1000),
            request_text=prompt_text,
            response_text=result,
            endpoint="/generate"
        )
        llm_monitor.log_request(llm_request)
        
        # Store conversation for judge analysis
        judge_system.store_conversation(
            session_id=request_id,
            user_id=user_ip,
            user_message=prompt_text,
            assistant_message=result,
            model=model_name
        )
        
    except Exception as e:
        logging.warning(f"Monitoring logging failed: {e}")
    
    return InferenceResponse(result=result, latency=latency)

# Endpoints supplémentaires pour le monitoring et l'administration

@app.get("/")
async def root():
    """
    Endpoint racine - redirection vers le dashboard
    """
    return {"message": "MLOps Monitoring Platform", "dashboard": "/dashboard", "metrics": "/metrics"}

@app.get("/health")
async def health_check():
    """Health check endpoint for Docker"""
    try:
        status = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "services": {
                "security_analyzer": security_analyzer is not None,
                "kpi_analyzer": kpi_analyzer is not None,
                "judge_system": judge_system is not None,
                "monitoring_dashboard": monitoring_dashboard is not None
            }
        }
        return JSONResponse(status)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")

@app.get("/api/security/stats")
async def get_security_stats():
    """
    Endpoint pour obtenir les statistiques de sécurité
    """
    if security_analyzer is None:
        return {"error": "Security analyzer not initialized", "total_threats": 0}
    
    return security_analyzer.get_threat_statistics()

@app.get("/api/usage/analytics")
async def get_usage_analytics(days: int = 7):
    """
    Endpoint pour obtenir les analytics d'usage
    """
    if kpi_analyzer is None:
        return {"error": "KPI analyzer not initialized", "analytics": {}}
    
    return kpi_analyzer.get_usage_analytics(days)

@app.get("/api/anomalies")
async def get_anomalies():
    """
    Endpoint pour obtenir les anomalies détectées
    """
    if kpi_analyzer is None:
        return {"error": "KPI analyzer not initialized", "anomalies": []}
    
    return kpi_analyzer.detect_anomalies()

@app.post("/api/security/analyze")
async def analyze_security(request: Request):
    """
    Endpoint pour analyser la sécurité d'un prompt spécifique
    """
    data = await request.json()
    prompt = data.get("prompt", "")
    user_id = data.get("user_id", "api_user")
    
    if not prompt:
        raise HTTPException(status_code=400, detail="Prompt requis")
    
    if security_analyzer is None:
        return {
            "risk_level": "unknown",
            "threats": [],
            "recommendations": ["Security analyzer not initialized"],
            "score": 0.0
        }
    
    analysis = security_analyzer.analyze_prompt(prompt, user_id)
    return analysis

@app.get("/api/models/performance")
async def get_model_performance():
    """
    Endpoint pour obtenir les performances des modèles
    """
    if kpi_analyzer is None:
        return {"model_performance": {}, "error": "KPI analyzer not initialized"}
    
    analytics = kpi_analyzer.get_usage_analytics(days=7)
    return analytics.get("model_performance", {})

@app.post("/api/admin/reset-stats")
async def reset_statistics():
    """
    Endpoint pour réinitialiser les statistiques (admin uniquement)
    """
    if security_analyzer is None:
        return {"error": "Security analyzer not initialized", "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())}
    
    security_analyzer.reset_statistics()
    return {"message": "Statistiques réinitialisées", "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())}

@app.get("/api/admin/system-info")
async def get_system_info():
    """
    Endpoint pour obtenir les informations système
    """
    security_threats = 0
    total_inferences = 0
    
    if security_analyzer is not None:
        try:
            security_threats = security_analyzer.get_threat_statistics()["total_threats"]
        except Exception:
            security_threats = 0
    
    if kpi_analyzer is not None:
        try:
            total_inferences = len(kpi_analyzer.usage_data)
        except Exception:
            total_inferences = 0
    
    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
        "available_models": list(MODEL_NAMES.keys()),
        "security_threats_detected": security_threats,
        "total_inferences_processed": total_inferences,
        "system_status": "operational"
    }

# Endpoint pour tester les alertes
@app.post("/api/test/security-alert")
async def test_security_alert():
    """
    Endpoint de test pour les alertes de sécurité
    """
    test_threat = {
        "risk_level": "HIGH",
        "threats_detected": ["test_injection"],
        "risk_score": 15,
        "user_id": "test_user",
        "prompt": "Test security alert"
    }
    
    if ai_agent:
        alert = ai_agent.generate_security_alert(test_threat)
        return alert
    else:
        return {"error": "AI agent not initialized", "test_threat": test_threat}

# LLM Judge System - Already initialized at top of file
# judge_system is created globally with SimpleJudgeSystem()

async def initialize_judge_system():
    """Initialize the judge system"""
    global judge_system
    try:
        # Judge system is already initialized as SimpleJudgeSystem
        # Just verify it's working
        if judge_system:
            logging.info("✅ Simple Judge System initialized successfully")
        else:
            logging.warning("⚠️ Judge System not initialized")
    except Exception as e:
        logging.error(f"❌ Failed to initialize Judge System: {e}")

@app.on_event("startup")
async def startup_event():
    """Initialize all services on startup"""
    global security_analyzer, kpi_analyzer, ai_analysis_agent, monitoring_dashboard, dashboard, ai_agent, judge_system
    
    try:
        # Initialize SecurityAnalyzer
        security_analyzer = SecurityAnalyzer()
        logger.info("SecurityAnalyzer initialized successfully")
        
        # Initialize KPIAnalyzer
        kpi_analyzer = KPIAnalyzer()
        logger.info("KPIAnalyzer initialized successfully")
        
        # Initialize AIAnalysisAgent
        ai_analysis_agent = AIAnalysisAgent()
        logger.info("AIAnalysisAgent initialized successfully")
        
        # Initialize MonitoringDashboard
        monitoring_dashboard = MonitoringDashboard(app)
        logger.info("MonitoringDashboard initialized successfully")
        
        # Set up aliases
        dashboard = monitoring_dashboard
        ai_agent = ai_analysis_agent
        
        # Initialize Judge System
        await initialize_judge_system()
        
        logger.info("All services initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize services: {e}")
        # Don't crash the app, just log the error

@app.get("/api/judge/intelligent-analysis")
async def get_intelligent_analysis(
    hours_back: int = 24,
    current_user: str = Depends(get_current_user_optional)
):
    """
    🎯 Generate AI-powered analysis of conversation data
    Analyzes conversations stored in our local database
    """
    try:
        if not judge_system:
            raise HTTPException(
                status_code=503, 
                detail="Judge System not available."
            )
        
        logging.info(f"Generating intelligent analysis for {hours_back} hours")
        
        # Get unanalyzed conversations and analyze them
        analysis_results = await judge_system.analyze_recent_conversations(hours_back=hours_back)
        
        insights = {
            "timestamp": datetime.now().isoformat(),
            "analysis_period_hours": hours_back,
            "conversations_analyzed": analysis_results.get("conversations_analyzed", 0),
            "high_risk_conversations": analysis_results.get("high_risk_count", 0),
            "average_risk_score": analysis_results.get("average_risk_score", 0),
            "risk_categories": analysis_results.get("risk_categories", {}),
            "detailed_analyses": analysis_results.get("analyses", [])
        }
        
        # Log the analysis request
        try:
            log_security_event(
                event_type="ai_analysis_requested",
                user_id=getattr(current_user, 'id', 'anonymous') if current_user else 'anonymous',
                severity="INFO",
                details={
                    "hours_analyzed": hours_back,
                    "analysis_timestamp": insights.get("timestamp"),
                    "conversations_analyzed": insights.get("conversations_analyzed", 0)
                }
            )
        except Exception as e:
            logging.warning(f"Failed to log analysis request: {e}")
        
        return insights
        
    except Exception as e:
        logging.error(f"Error in intelligent analysis: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/api/judge/user-analysis/{user_id}")
async def get_user_analysis(
    user_id: str, 
    hours_back: int = 24,
    current_user: str = Depends(get_current_user_optional)
):
    """
    Get detailed AI analysis for a specific user
    """
    try:
        if not judge_system:
            raise HTTPException(status_code=503, detail="Judge System not available")
        
        logging.info(f"Analyzing user {user_id} for {hours_back} hours")
        
        # Get user's conversations and analyze them
        user_analysis = await judge_system.analyze_user_conversations(user_id, hours_back=hours_back)
        
        if not user_analysis or user_analysis.get("conversations_count", 0) == 0:
            return {
                "message": f"No data found for user {user_id} in the last {hours_back} hours",
                "user_id": user_id,
                "analysis_period": f"{hours_back} hours",
                "timestamp": datetime.now().isoformat()
            }
        
        result = user_analysis
        result["analysis_timestamp"] = datetime.now().isoformat()
        result["analysis_period"] = f"{hours_back} hours"
        
        return result
        
    except Exception as e:
        logging.error(f"Error in user analysis for {user_id}: {e}")
        raise HTTPException(status_code=500, detail=f"User analysis failed: {str(e)}")

@app.get("/api/judge/system-health")
async def get_system_health_analysis(
    hours_back: int = 24,
    current_user: str = Depends(get_current_user_optional)
):
    """
    Get AI-powered system health analysis
    """
    try:
        if not judge_system:
            raise HTTPException(status_code=503, detail="Judge System not available")
        
        logging.info(f"Analyzing system health for {hours_back} hours")
        
        # Get system-wide analysis
        system_analysis = await judge_system.analyze_system_health(hours_back=hours_back)
        
        result = system_analysis
        result["analysis_timestamp"] = datetime.now().isoformat()
        
        return result
        
    except Exception as e:
        logging.error(f"Error in system health analysis: {e}")
        raise HTTPException(status_code=500, detail=f"System analysis failed: {str(e)}")

@app.get("/api/judge/risk-dashboard")
async def get_risk_dashboard(
    hours_back: int = 24,
    risk_level: str = None,
    current_user: str = Depends(get_current_user_optional)
):
    """
    Get risk dashboard with user risk levels and system alerts
    """
    try:
        if not judge_system:
            raise HTTPException(status_code=503, detail="Judge System not available")
        
        # Get risk dashboard data from our simple judge system
        dashboard_data = await judge_system.get_risk_dashboard(hours_back=hours_back, risk_level=risk_level)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "analysis_period_hours": hours_back,
            **dashboard_data,
            "filter_applied": risk_level
        }
        
    except Exception as e:
        logging.error(f"Error in risk dashboard: {e}")
        raise HTTPException(status_code=500, detail=f"Risk dashboard failed: {str(e)}")

# Add a scheduled task to run analysis periodically
@app.get("/api/judge/run-scheduled-analysis")
async def run_scheduled_analysis(current_user: str = Depends(get_current_user_optional)):
    """
    Run scheduled analysis and store results
    This can be called by a cron job or scheduled task
    """
    try:
        if not judge_system:
            return {"error": "LLM Judge System not available"}
        
        logging.info("Running scheduled AI analysis...")
        
        # Run analysis for last 24 hours
        insights = await judge_system.generate_intelligent_insights(hours_back=24)
        
        # Store results in database for historical tracking
        try:
            # You can add database storage here
            pass
        except Exception as e:
            logging.warning(f"Failed to store analysis results: {e}")
        
        # Send alerts for high-risk findings
        high_risk_count = insights.get("user_risk_assessment", {}).get("high_risk_users", 0)
        critical_risk_count = insights.get("user_risk_assessment", {}).get("critical_risk_users", 0)
        
        if high_risk_count > 0 or critical_risk_count > 0:
            # Send alert email or notification
            alert_message = f"🚨 AI Analysis Alert: {critical_risk_count} critical and {high_risk_count} high-risk users detected"
            logging.warning(alert_message)
            
            # You can integrate with your existing alert system here
            try:
                # send_alert_email(alert_message, insights)
                pass
            except Exception as e:
                logging.error(f"Failed to send analysis alert: {e}")
        
        return {
            "status": "completed",
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "users_analyzed": insights.get("user_risk_assessment", {}).get("total_users_analyzed", 0),
                "high_risk_users": high_risk_count,
                "critical_risk_users": critical_risk_count,
                "security_concerns": len(insights.get("system_analysis", {}).get("security_concerns", [])),
                "recommendations": len(insights.get("actionable_recommendations", []))
            }
        }
        
    except Exception as e:
        logging.error(f"Error in scheduled analysis: {e}")
        return {"error": f"Scheduled analysis failed: {str(e)}"}

# LLM Monitoring and Observability Endpoints

@app.get("/api/llm/usage-stats")
async def get_llm_usage_stats(hours: int = 24):
    """
    Get LLM usage statistics and cost tracking
    ✅ Replaces Langfuse observability
    """
    try:
        stats = llm_monitor.get_usage_stats(hours=hours)
        return {
            "status": "success",
            "period_hours": hours,
            **stats
        }
    except Exception as e:
        logging.error(f"Error getting LLM usage stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get usage stats: {str(e)}")

@app.get("/api/llm/cost-tracking")
async def get_cost_tracking(hours: int = 24):
    """
    Get detailed cost tracking for LLM usage
    ✅ Replaces Langfuse cost tracking
    """
    try:
        stats = llm_monitor.get_usage_stats(hours=hours)
        
        return {
            "status": "success",
            "period_hours": hours,
            "cost_summary": {
                "total_cost_usd": stats.get("total_cost", 0),
                "total_requests": stats.get("total_requests", 0),
                "cost_per_request": stats.get("total_cost", 0) / max(stats.get("total_requests", 1), 1),
                "models": stats.get("models", [])
            },
            "recommendations": [
                "Consider using smaller models for simple tasks",
                "Monitor high-cost users and conversations",
                "Set up cost alerts for budget management"
            ]
        }
    except Exception as e:
        logging.error(f"Error getting cost tracking: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get cost tracking: {str(e)}")

@app.get("/api/llm/requests")
async def get_recent_requests(limit: int = 50, status: str = None):
    """
    Get recent LLM requests with details
    ✅ Provides LLM request observability
    """
    try:
        requests = llm_monitor.get_recent_requests(limit=limit, status=status)
        return {
            "status": "success",
            "requests": requests,
            "total_returned": len(requests)
        }
    except Exception as e:
        logging.error(f"Error getting recent requests: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get requests: {str(e)}")

@app.get("/api/llm/performance")
async def get_llm_performance(hours: int = 24):
    """
    Get LLM performance metrics
    ✅ Provides performance monitoring
    """
    try:
        # Get performance data from our monitoring
        query = """
        SELECT 
            model,
            AVG(latency_ms) as avg_latency,
            MIN(latency_ms) as min_latency,
            MAX(latency_ms) as max_latency,
            COUNT(*) as request_count,
            COUNT(CASE WHEN status = 'error' THEN 1 END) as error_count
        FROM llm_requests 
        WHERE timestamp > NOW() - INTERVAL %s
        GROUP BY model
        ORDER BY request_count DESC
        """
        
        performance_data = []
        
        with llm_monitor._get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query, (f"{hours} hours",))
                results = cursor.fetchall()
                
                for row in results:
                    model, avg_lat, min_lat, max_lat, req_count, err_count = row
                    performance_data.append({
                        "model": model,
                        "average_latency_ms": float(avg_lat or 0),
                        "min_latency_ms": float(min_lat or 0),
                        "max_latency_ms": float(max_lat or 0),
                        "request_count": req_count,
                        "error_count": err_count,
                        "success_rate": ((req_count - err_count) / max(req_count, 1)) * 100
                    })
        
        return {
            "status": "success",
            "period_hours": hours,
            "performance_by_model": performance_data,
            "summary": {
                "total_requests": sum(p["request_count"] for p in performance_data),
                "total_errors": sum(p["error_count"] for p in performance_data),
                "overall_success_rate": sum(p["success_rate"] * p["request_count"] for p in performance_data) / max(sum(p["request_count"] for p in performance_data), 1)
            }
        }
        
    except Exception as e:
        logging.error(f"Error getting performance metrics: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get performance metrics: {str(e)}")

@app.get("/api/monitoring/dashboard")
async def get_monitoring_dashboard():
    """
    Get comprehensive monitoring dashboard data
    ✅ Replaces Langfuse dashboard with local monitoring
    """
    try:
        # Get LLM usage stats
        llm_stats = llm_monitor.get_usage_stats(hours=24)
        
        # Get judge system stats
        judge_stats = judge_system.get_risk_summary(hours=24)
        
        # Get recent high-risk conversations
        risk_dashboard = await judge_system.get_risk_dashboard(hours_back=24)
        
        return {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "llm_observability": {
                "total_requests": llm_stats.get("total_requests", 0),
                "total_cost": llm_stats.get("total_cost", 0),
                "models_used": len(llm_stats.get("models", [])),
                "top_models": llm_stats.get("models", [])[:5]
            },
            "cost_tracking": {
                "daily_cost": llm_stats.get("total_cost", 0),
                "avg_cost_per_request": llm_stats.get("total_cost", 0) / max(llm_stats.get("total_requests", 1), 1),
                "budget_alerts": []  # Could add budget threshold alerts
            },
            "judge_analysis": {
                "conversations_analyzed": judge_stats.get("analyzed_count", 0),
                "high_risk_users": risk_dashboard.get("risk_summary", {}).get("high_risk_users", 0),
                "critical_users": risk_dashboard.get("risk_summary", {}).get("critical_users", 0),
                "analysis_coverage": judge_stats.get("analysis_coverage", "0%")
            },
            "performance_monitoring": {
                "system_health": "healthy",  # Could add more sophisticated health checks
                "response_times": "normal",
                "error_rates": "low"
            },
            "recommendations": [
                "✅ LLM observability: All requests are being tracked",
                "✅ Cost tracking: Real-time cost monitoring active",
                "✅ Judge analysis: Conversation risk analysis running",
                "✅ Performance monitoring: Latency and error tracking active",
                "💡 Consider setting up cost alerts for budget management",
                "💡 Review high-risk conversations in the judge dashboard"
            ]
        }
        
    except Exception as e:
        logging.error(f"Error getting monitoring dashboard: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard: {str(e)}")

# Add this to your request middleware
@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    """Middleware to track request metrics"""
    start_time = time.time()
    
    try:
        response = await call_next(request)
        
        # Record successful request
        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=request.url.path,
            status=response.status_code
        ).inc()
        
        REQUEST_LATENCY.observe(time.time() - start_time)
        
        return response
        
    except Exception as e:
        # Record failed request
        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=request.url.path,
            status=500
        ).inc()
        
        REQUEST_LATENCY.observe(time.time() - start_time)
        raise