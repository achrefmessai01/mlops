from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import os
import requests
from langfuse import Langfuse
import logging
import time
from typing import List, Optional, Any
from dotenv import load_dotenv
import traceback
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
import re
import json

# Importer nos modules d'analyse
from security_analyzer import SecurityAnalyzer
from kpi_analyzer import KPIAnalyzer
from ai_analysis_agent import AIAnalysisAgent
from monitoring_dashboard import MonitoringDashboard

app = FastAPI(title="MLOps Monitoring Platform", description="Plateforme de monitoring et analyse des inférences IA")

# Initialiser les analyseurs et le dashboard
security_analyzer = SecurityAnalyzer()
kpi_analyzer = KPIAnalyzer()
ai_agent = AIAnalysisAgent()
dashboard = MonitoringDashboard(app)

# Servir les fichiers statiques
app.mount("/static", StaticFiles(directory="static"), name="static")

# Load model API keys from .env file
load_dotenv(os.path.join(os.path.dirname(__file__), "model_api_keys.env"))

# Configure logging
logging.basicConfig(level=logging.INFO, filename='logs/inference.log', filemode='a', format='%(asctime)s %(message)s')

# Langfuse setup using environment variables
langfuse = Langfuse(
    secret_key=os.getenv("LANGFUSE_SECRET_KEY"),
    public_key=os.getenv("LANGFUSE_PUBLIC_KEY"),
    host=os.getenv("LANGFUSE_HOST")
)

# OpenRouter API key (single key for all models)
OPENROUTER_API_KEY = "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"

# Gemini API key
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

MODEL_NAMES = {
    "qwendeepseek": "deepseek/deepseek-r1-0528-qwen3-8b:free",
    "gemma3n": "google/gemma-3n-e4b-it:free",  
    "llama4": "meta-llama/llama-4-maverick:free",
    "mistral": "mistralai/mistral-small-3.2-24b-instruct:free",
    "gemini": "gemini-2.0-flash"  # Direct Gemini API
}

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

class MessageContent(BaseModel):
    type: str  # 'text' or 'image_url'
    text: Optional[str] = None
    image_url: Optional[dict] = None

class Message(BaseModel):
    role: str  # 'user', 'system', etc.
    content: List[MessageContent]

class InferenceRequest(BaseModel):
    model_name: str  # 'qwen', 'gemma', or 'llama4'
    messages: List[Message] = Field(..., description="List of chat messages, each with content (text and/or image_url)")

class InferenceResponse(BaseModel):
    result: str
    latency: float


# Prometheus metrics
INFERENCES_TOTAL = Counter(
    'inference_requests_total', 'Total number of inference requests', ['endpoint', 'model', 'user']
)
INFERENCE_LATENCY = Histogram(
    'inference_latency_seconds', 'Inference latency in seconds', ['endpoint', 'model', 'user']
)
PROMPT_LENGTH = Histogram(
    'prompt_length', 'Length of prompts', ['endpoint', 'model', 'user']
)
RESPONSE_LENGTH = Histogram(
    'response_length', 'Length of responses', ['endpoint', 'model', 'user']
)

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
    return response.json()["choices"][0]["message"]["content"]

def call_gemini_api(messages):
    """Call Google Gemini API directly"""
    if not GEMINI_API_KEY:
        raise Exception("GEMINI_API_KEY not configured")
    
    # Convert messages to Gemini format
    contents = []
    for msg in messages:
        parts = []
        for part in msg.content:
            if part.type == "text" and part.text:
                parts.append({"text": part.text})
            # Add image support later if needed
        if parts:
            contents.append({"parts": parts})
    
    data = {"contents": contents}
    
    headers = {
        "Content-Type": "application/json"
    }
    
    url = f"{GEMINI_URL}?key={GEMINI_API_KEY}"
    
    logging.info(f"Gemini payload: {data}")
    
    try:
        response = requests.post(
            url=url,
            headers=headers,
            json=data,
            timeout=60
        )
        response.raise_for_status()
        resp_json = response.json()
        
        if "candidates" not in resp_json:
            logging.error(f"Gemini API unexpected response: {resp_json}")
            raise Exception(f"Gemini API did not return 'candidates': {resp_json}")
        
        # Extract the text from the response
        candidate = resp_json["candidates"][0]
        content = candidate["content"]["parts"][0]["text"]
        return content
        
    except requests.exceptions.HTTPError as e:
        try:
            error_detail = response.json()
        except Exception:
            error_detail = response.text
        logging.error(f"Gemini API error response: {error_detail}")
        raise Exception(f"{e} | Gemini response: {error_detail}")

@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

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
    
    # Prometheus metrics: count and observe
    INFERENCES_TOTAL.labels(endpoint, model_name, user_ip).inc()
    prompt_len = len(prompt_text)
    PROMPT_LENGTH.labels(endpoint, model_name, user_ip).observe(prompt_len)

    try:
        if model_name == "gemini":
            result = call_gemini_api(body.messages)
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
    INFERENCE_LATENCY.labels(endpoint, model_name, user_ip).observe(latency)
    RESPONSE_LENGTH.labels(endpoint, model_name, user_ip).observe(len(result))
    
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
    dashboard.log_inference(log_data)
    
    # Send to Langfuse with structured input
    try:
        langfuse.create_event(
            name="inference",
            input=log_data
        )
    except Exception as e:
        logging.warning(f"Langfuse logging failed: {e}")
    
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
    """
    Endpoint de santé pour les checks de monitoring
    """
    return {
        "status": "healthy",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
        "services": {
            "langfuse": "connected" if langfuse else "disconnected",
            "security_analyzer": "active",
            "kpi_analyzer": "active",
            "ai_agent": "active"
        }
    }

@app.get("/api/security/stats")
async def get_security_stats():
    """
    Endpoint pour obtenir les statistiques de sécurité
    """
    return security_analyzer.get_threat_statistics()

@app.get("/api/usage/analytics")
async def get_usage_analytics(days: int = 7):
    """
    Endpoint pour obtenir les analytics d'usage
    """
    return kpi_analyzer.get_usage_analytics(days)

@app.get("/api/anomalies")
async def get_anomalies():
    """
    Endpoint pour obtenir les anomalies détectées
    """
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
    
    analysis = security_analyzer.analyze_prompt(prompt, user_id)
    return analysis

@app.get("/api/models/performance")
async def get_model_performance():
    """
    Endpoint pour obtenir les performances des modèles
    """
    analytics = kpi_analyzer.get_usage_analytics(days=7)
    return analytics.get("model_performance", {})

@app.post("/api/admin/reset-stats")
async def reset_statistics():
    """
    Endpoint pour réinitialiser les statistiques (admin uniquement)
    """
    security_analyzer.reset_statistics()
    return {"message": "Statistiques réinitialisées", "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())}

@app.get("/api/admin/system-info")
async def get_system_info():
    """
    Endpoint pour obtenir les informations système
    """
    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
        "available_models": list(MODEL_NAMES.keys()),
        "security_threats_detected": security_analyzer.get_threat_statistics()["total_threats"],
        "total_inferences_processed": len(kpi_analyzer.usage_data),
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
    
    alert = ai_agent.generate_security_alert(test_threat)
    return alert
