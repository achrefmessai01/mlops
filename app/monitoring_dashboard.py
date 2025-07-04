"""
Dashboard de monitoring pour la plateforme MLOps
"""
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import json
import os
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, List
import logging
import psycopg2
from psycopg2.extras import Json
import ipaddress

# Importer nos modules d'analyse
from security_analyzer import SecurityAnalyzer
from kpi_analyzer import KPIAnalyzer
from ai_analysis_agent import AIAnalysisAgent

class MonitoringDashboard:
    def __init__(self, app: FastAPI):
        self.app = app
        self.templates = Jinja2Templates(directory="templates")
        self.security_analyzer = SecurityAnalyzer()
        self.kpi_analyzer = KPIAnalyzer()
        self.ai_agent = AIAnalysisAgent()
        self.logger = logging.getLogger(__name__)
        
        # Cache simple pour les recommandations
        self._recommendations_cache = None
        self._recommendations_cache_time = None
        self._cache_duration = 5  # 5 seconds for testing
        
        # Créer le dossier templates s'il n'existe pas
        os.makedirs("templates", exist_ok=True)
        os.makedirs("static", exist_ok=True)
        
        # Database connection setup
        try:
            self.db_conn = psycopg2.connect(
                dbname=os.getenv("POSTGRES_DB", "mlops"),
                user=os.getenv("POSTGRES_USER", "mlops"),
                password=os.getenv("POSTGRES_PASSWORD", "mlops"),
                host=os.getenv("POSTGRES_HOST", "localhost"),
                port=os.getenv("POSTGRES_PORT", "5432")
            )
            self.db_conn.autocommit = True
            self.db_cursor = self.db_conn.cursor()
            self.logger.info("Database connection established successfully")
        except Exception as e:
            self.logger.error(f"Database connection failed: {e}")
            self.db_conn = None
            self.db_cursor = None
        
        # Ajouter les routes du dashboard
        self._setup_routes()
        
    def _setup_routes(self):
        """
        Configure les routes du dashboard
        """
        
        @self.app.get("/dashboard", response_class=HTMLResponse)
        async def dashboard_home(request: Request):
            return self.templates.TemplateResponse("dashboard.html", {"request": request})
        
        @self.app.get("/api/dashboard/overview")
        async def dashboard_overview():
            """
            API pour obtenir les données de vue d'ensemble
            """
            try:
                # Récupérer les métriques - fail fast if no real data
                security_stats = self.security_analyzer.get_threat_statistics()
                # Générer l'intelligence de menaces avancée
                threat_intelligence = self.security_analyzer.generate_threat_intelligence()
                
                usage_analytics = self.kpi_analyzer.get_usage_analytics(days=7)
                if "error" in usage_analytics:
                    raise HTTPException(status_code=500, detail="Pas de données d'usage disponibles")
                
                anomalies = self.kpi_analyzer.detect_anomalies()
                
                # Process enhanced security breakdown to get keyword data
                enhanced_breakdown = self._process_enhanced_security_breakdown(security_stats.get("threat_breakdown", {}))
                
                overview = {
                    "timestamp": datetime.now().isoformat(),
                    "security": {
                        "total_threats": security_stats.get("total_threats", 0),
                        "threat_level": threat_intelligence.get("threat_level", "LOW"),
                        "breakdown": security_stats.get("threat_breakdown", {}),
                        "enhanced_breakdown": enhanced_breakdown,
                        "threat_intelligence": threat_intelligence,
                        "high_severity_threats": security_stats.get("threat_breakdown", {}).get("high_severity_threats", 0),
                        "multi_vector_attacks": security_stats.get("threat_breakdown", {}).get("multi_vector_attacks", 0),
                        "repeated_offenders": security_stats.get("threat_breakdown", {}).get("repeated_offenders", 0)
                    },
                    # Add keyword breakdown for frontend compatibility
                    "keyword_breakdown": self._extract_keyword_breakdown_for_frontend(enhanced_breakdown),
                    "usage": {
                        "total_requests": usage_analytics.get("general_metrics", {}).get("total_requests", 0),
                        "avg_latency": usage_analytics.get("general_metrics", {}).get("avg_latency", 0),
                        "unique_users": usage_analytics.get("general_metrics", {}).get("unique_users", 0),
                        "requests_per_day": usage_analytics.get("general_metrics", {}).get("avg_requests_per_day", 0)
                    },
                    "anomalies": {
                        "count": len(anomalies.get("detected_anomalies", [])),
                        "types": [a.get("type") for a in anomalies.get("detected_anomalies", [])]
                    }
                }
                
                return JSONResponse(content=overview)
                
            except Exception as e:
                self.logger.error(f"Erreur dans dashboard_overview: {e}")
                # Raise exception instead of returning mock data - let frontend handle error
                raise HTTPException(status_code=500, detail=f"Erreur lors de la récupération des données du dashboard: {str(e)}")
        
        @self.app.get("/api/dashboard/security")
        async def dashboard_security():
            """
            API pour les données de sécurité détaillées
            """
            try:
                stats = self.security_analyzer.get_threat_statistics()
                return JSONResponse(content=stats)
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/dashboard/performance")
        async def dashboard_performance():
            """
            API pour les métriques de performance
            """
            try:
                analytics = self.kpi_analyzer.get_usage_analytics(days=7)
                return JSONResponse(content=analytics)
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/dashboard/anomalies")
        async def dashboard_anomalies():
            """
            API pour les anomalies détectées
            """
            try:
                anomalies = self.kpi_analyzer.detect_anomalies()
                return JSONResponse(content=anomalies)
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/dashboard/recommendations")
        async def dashboard_recommendations():
            """
            API pour les recommandations de l'IA avec cache et fallback rapide
            """
            try:
                # Vérifier le cache d'abord
                now = datetime.now()
                if (self._recommendations_cache is not None and 
                    self._recommendations_cache_time is not None and
                    (now - self._recommendations_cache_time).seconds < self._cache_duration):
                    self.logger.info("Retour des recommandations en cache")
                    return JSONResponse(content=self._recommendations_cache)
                
                # Collecter toutes les données - fail fast if no real data
                security_data = self.security_analyzer.get_threat_statistics()
                kpi_data = self.kpi_analyzer.get_usage_analytics(days=7)
                if "error" in kpi_data:
                    raise HTTPException(status_code=500, detail="Pas de données KPI disponibles")
                
                anomalies = self.kpi_analyzer.detect_anomalies()
                prompt_analysis = self.kpi_analyzer.get_prompt_analysis()
                
                # Analyse IA uniquement - pas de fallback avec données fictives
                try:
                    self.logger.info("Analyse IA en cours...")
                    
                    # Initialize variables
                    ai_success = False
                    ai_error = None
                    recommendations = None
                    
                    # Pour Windows, utiliser threading au lieu de signal
                    def ai_analysis_task():
                        nonlocal recommendations, ai_success, ai_error
                        try:
                            recommendations = self.ai_agent.generate_comprehensive_analysis(
                                security_data, kpi_data, anomalies, prompt_analysis
                            )
                            ai_success = True
                        except Exception as e:
                            ai_error = e
                            ai_success = False
                    
                    # Lancer l'analyse IA dans un thread avec timeout
                    thread = threading.Thread(target=ai_analysis_task)
                    thread.daemon = True
                    thread.start()
                    thread.join(timeout=30)  # 30 secondes max pour l'analyse IA
                    
                    if ai_success and recommendations:
                        # Vérifier que la structure est correcte
                        if not isinstance(recommendations, dict):
                            raise ValueError("Réponse de l'IA malformée")
                        
                        # Log the AI response structure
                        print(f"[DEBUG] AI response keys: {list(recommendations.keys())}")
                        if "recommendations" in recommendations:
                            print(f"[DEBUG] Number of AI recommendations: {len(recommendations['recommendations'])}")
                            if recommendations['recommendations']:
                                print(f"[DEBUG] First AI recommendation keys: {list(recommendations['recommendations'][0].keys())}")
                                print(f"[DEBUG] First AI recommendation: {json.dumps(recommendations['recommendations'][0], indent=2)}")
                        
                        # S'assurer que les champs requis existent
                        if "recommendations" not in recommendations:
                            recommendations["recommendations"] = []
                        
                        # Map executive_summary to summary for dashboard compatibility
                        if "executive_summary" in recommendations and "summary" not in recommendations:
                            recommendations["summary"] = recommendations["executive_summary"]
                            self.logger.info("Mapped executive_summary to summary for dashboard")
                        
                        # Clean up unwanted summary fields from successful AI analysis
                        if len(recommendations.get("recommendations", [])) > 0:
                            # We have recommendations, so remove any generic summary
                            if "summary" in recommendations:
                                summary_text = recommendations["summary"]
                                # Remove if it's a generic/fallback message
                                if any(phrase in summary_text for phrase in [
                                    "terminée sans recommandations",
                                    "Service IA juge indisponible", 
                                    "Analyse automatique de base"
                                ]):
                                    del recommendations["summary"]
                                    self.logger.info("Removed generic summary from successful AI analysis")
                        
                        # Only add default summary if no recommendations exist
                        elif len(recommendations.get("recommendations", [])) == 0:
                            if "summary" not in recommendations:
                                recommendations["summary"] = "Aucune recommandation générée pour cette analyse."
                        
                        # Log before caching
                        print(f"[DEBUG] Before caching - recommendations keys: {list(recommendations.keys())}")
                        
                        # Mettre en cache le résultat
                        self._recommendations_cache = recommendations
                        self._recommendations_cache_time = now
                        
                        self.logger.info("Analyse IA réussie")
                        return JSONResponse(content=recommendations)
                    else:
                        # Fallback avec données par défaut
                        self.logger.warning("Analyse IA échouée, utilisation du fallback détaillé")
                        fallback_recommendations = {
                            "summary": "Analyse automatique - Service IA temporairement indisponible",
                            "recommendations": [
                                {
                                    "priority": "MEDIUM",
                                    "category": "MONITORING",
                                    "title": "Surveillance en temps réel active",
                                    "description": "Le système continue la surveillance malgré l'indisponibilité de l'IA",
                                    "action_items": [
                                        "Continuer la surveillance en temps réel",
                                        "Vérifier les logs système",
                                        "Contrôler la connectivité réseau"
                                    ],
                                    "impact": "Surveillance continue assurée",
                                    "timeline": "En cours"
                                },
                                {
                                    "priority": "LOW",
                                    "category": "SYSTEM",
                                    "title": "Reconnexion AI en attente",
                                    "description": "Service d'analyse IA en attente de rétablissement automatique",
                                    "action_items": [
                                        "Vérifier la connectivité AI dans 5 minutes",
                                        "Surveiller les performances système"
                                    ],
                                    "impact": "Fonctionnalités réduites temporairement",
                                    "timeline": "5-10 minutes"
                                }
                            ],
                            "metadata": {
                                "analysis_type": "fallback",
                                "generated_at": datetime.now().isoformat(),
                                "status": "Service IA indisponible"
                            }
                        }
                        
                        # Mettre en cache le résultat de fallback
                        self._recommendations_cache = fallback_recommendations
                        self._recommendations_cache_time = now
                        
                        return JSONResponse(content=fallback_recommendations)
                    
                except Exception as ai_error:
                    self.logger.error(f"Erreur lors de l'analyse IA: {ai_error}")
                    raise HTTPException(status_code=503, detail="Service d'analyse IA temporairement indisponible")
                
            except Exception as e:
                self.logger.error(f"Erreur dans dashboard_recommendations: {e}")
                raise HTTPException(status_code=500, detail=f"Erreur lors de la génération des recommandations: {str(e)}")
        
        @self.app.get("/api/dashboard/alerts")
        async def dashboard_alerts():
            """
            API pour les alertes actives
            """
            try:
                # Utiliser AlertManager si disponible
                try:
                    from alert_system import AlertManager
                    global_alert_manager = getattr(self, 'alert_manager', None)
                    if global_alert_manager and hasattr(global_alert_manager, 'get_alerts_api'):
                        return JSONResponse(content=global_alert_manager.get_alerts_api())
                except Exception as import_err:
                    self.logger.warning(f"AlertManager not used or failed: {import_err}")

                alerts = []
                # Vérifier les menaces de sécurité
                security_stats = self.security_analyzer.get_threat_statistics()
                if security_stats.get("total_threats", 0) > 5:
                    alerts.append({
                        "type": "security",
                        "level": "warning" if security_stats["total_threats"] < 10 else "critical",
                        "message": f"{security_stats['total_threats']} menaces de sécurité détectées",
                        "timestamp": datetime.now().isoformat()
                    })
                
                # Vérifier les anomalies
                anomalies = self.kpi_analyzer.detect_anomalies()
                for anomaly in anomalies.get("detected_anomalies", []):
                    alerts.append({
                        "type": "anomaly",
                        "level": "warning",
                        "message": f"Anomalie détectée: {anomaly.get('type')}",
                        "timestamp": datetime.now().isoformat(),
                        "details": anomaly
                    })
                
                # Vérifier les performances
                usage_analytics = self.kpi_analyzer.get_usage_analytics(days=1)
                avg_latency = usage_analytics.get("general_metrics", {}).get("avg_latency", 0)
                if avg_latency > 5000.0:  # 5000ms = 5s
                    alerts.append({
                        "type": "performance",
                        "level": "warning",
                        "message": f"Latence élevée: {avg_latency:.2f}ms",
                        "timestamp": datetime.now().isoformat()
                    })
                
                return JSONResponse(content={"alerts": alerts, "count": len(alerts)})
            except Exception as e:
                self.logger.error(f"Erreur dans dashboard_alerts: {e}")
                raise HTTPException(status_code=500, detail=f"Erreur lors de la récupération des alertes: {str(e)}")
        
        @self.app.post("/api/dashboard/analyze-prompt")
        async def analyze_prompt_security(request: Request):
            """
            API pour analyser un prompt spécifique
            """
            try:
                data = await request.json()
                prompt = data.get("prompt", "")
                user_id = data.get("user_id", "unknown")
                
                if not prompt:
                    raise HTTPException(status_code=400, detail="Prompt requis")
                
                analysis = self.security_analyzer.analyze_prompt(prompt, user_id)
                return JSONResponse(content=analysis)
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/dashboard/daily-report")
        async def daily_report():
            """
            API pour le rapport quotidien
            """
            try:
                # Collecter toutes les données - fail fast if no real data
                security_data = self.security_analyzer.get_threat_statistics()
                usage_data = self.kpi_analyzer.get_usage_analytics(days=1)
                if "error" in usage_data:
                    raise HTTPException(status_code=500, detail="Pas de données d'usage disponibles pour le rapport quotidien")
                
                anomalies_data = self.kpi_analyzer.detect_anomalies()
                prompts_data = self.kpi_analyzer.get_prompt_analysis()
                
                all_data = {
                    "security": security_data,
                    "usage": usage_data,
                    "anomalies": anomalies_data,
                    "prompts": prompts_data
                }
                
                # Générer le rapport avec l'IA - fail fast si pas disponible
                report = self.ai_agent.generate_daily_executive_report(all_data)
                
                return JSONResponse(content={
                    "report": report,
                    "generated_at": datetime.now().isoformat(),
                    "data_summary": {
                        "total_threats": security_data.get("total_threats", 0),
                        "total_requests": usage_data.get("general_metrics", {}).get("total_requests", 0),
                        "anomalies_count": len(anomalies_data.get("detected_anomalies", [])),
                        "prompts_analyzed": prompts_data.get("total_prompts", 0)
                    }
                })
                
            except Exception as e:
                self.logger.error(f"Erreur dans daily_report: {e}")
                raise HTTPException(status_code=500, detail=f"Erreur lors de la génération du rapport quotidien: {str(e)}")
        
        @self.app.get("/api/dashboard/export/{data_type}")
        async def export_data(data_type: str):
            """
            API pour exporter les données
            """
            try:
                if data_type == "security":
                    data = self.security_analyzer.get_threat_statistics()
                elif data_type == "usage":
                    data = self.kpi_analyzer.get_usage_analytics(days=30)
                elif data_type == "anomalies":
                    data = self.kpi_analyzer.detect_anomalies()
                elif data_type == "prompts":
                    data = self.kpi_analyzer.get_prompt_analysis()
                else:
                    raise HTTPException(status_code=400, detail="Type de données non supporté")
                
                # Ajouter les métadonnées d'export
                export_data = {
                    "exported_at": datetime.now().isoformat(),
                    "data_type": data_type,
                    "data": data
                }
                
                return JSONResponse(content=export_data)
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
    
    def log_inference(self, log_entry: Dict[str, Any]):
        """
        Traite une entrée de log d'inférence et l'insère dans la base Postgres
        """
        try:
            # Traiter pour les KPI (in-memory)
            self.kpi_analyzer.process_inference_log(log_entry)

            # --- PATCH: Ensure user_ip is valid, timestamp is set, and all required fields are present ---
            # Extract user_ip: must be a valid IPv4/IPv6 string or None
            user_ip = log_entry.get("user_ip") or log_entry.get("user")
            if user_ip is not None:
                try:
                    user_ip = str(ipaddress.ip_address(user_ip))
                except Exception:
                    self.logger.warning(f"user_ip value is not a valid IP: {user_ip}, setting to None")
                    user_ip = None
            # If not available, use None (will insert NULL)

            # Set timestamp if missing
            if not log_entry.get("timestamp"):
                log_entry["timestamp"] = datetime.now()

            # Defensive: ensure all required fields are present (except user_ip, which can be None)
            required_fields = [
                "timestamp", "endpoint", "model", "prompt", "prompt_length", "response", "response_length", "latency"
            ]
            for field in required_fields:
                if log_entry.get(field) is None:
                    self.logger.error(f"Champ manquant dans log_entry: {field} => {log_entry}")
                    raise ValueError(f"Champ manquant dans log_entry: {field}")

            # Insert into Postgres
            try:
                self.db_cursor.execute(
                    """
                    INSERT INTO inference_logs (
                        timestamp, user_ip, endpoint, model, prompt, prompt_length, response, response_length, latency_ms, security_analysis, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    """,
                    (
                        log_entry.get("timestamp"),
                        user_ip,
                        log_entry.get("endpoint"),
                        log_entry.get("model"),
                        log_entry.get("prompt"),
                        log_entry.get("prompt_length"),
                        log_entry.get("response"),
                        log_entry.get("response_length"),
                        int(log_entry.get("latency", 0) * 1000),  # Convert seconds to milliseconds
                        Json(log_entry.get("security_analysis", {}))
                    )
                )
            except Exception as db_exc:
                self.logger.error(f"Erreur lors de l'insertion dans inference_logs: {db_exc} | log_entry: {log_entry}")
                raise  # Surface DB errors for debugging

            # Analyser la sécurité du prompt
            if log_entry.get("prompt"):
                security_analysis = self.security_analyzer.analyze_prompt(
                    log_entry["prompt"], 
                    user_ip or "unknown"
                )
                # Log des menaces critiques
                if security_analysis["risk_level"] in ["HIGH", "CRITICAL"]:
                    self.logger.warning(f"SECURITY_ALERT: {security_analysis}")
                    # Générer une alerte si critique
                    if security_analysis["risk_level"] == "CRITICAL":
                        alert = self.ai_agent.generate_security_threat_analysis(security_analysis)
                        if alert:
                            self.logger.critical(f"CRITICAL_SECURITY_ALERT: {alert}")
        except Exception as e:
            self.logger.error(f"Erreur lors du traitement du log: {e} | log_entry: {log_entry}")
            raise
    
    def get_dashboard_summary(self) -> Dict[str, Any]:
        """
        Obtient un résumé pour le dashboard
        """
        try:
            return {
                "security": self.security_analyzer.get_threat_statistics(),
                "usage": self.kpi_analyzer.get_usage_analytics(days=7),
                "anomalies": self.kpi_analyzer.detect_anomalies(),
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Erreur dans get_dashboard_summary: {e}")
            return {"error": str(e)}
    
    def _process_enhanced_security_breakdown(self, threat_breakdown: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process enhanced security breakdown for dashboard visualization
        """
        # Categorize threats into main categories and keyword categories
        main_categories = {
            "system_override": 0,
            "info_extraction": 0,
            "jailbreak_advanced": 0,
            "social_engineering": 0,
            "credential_harvesting": 0,
            "code_injection": 0,
            "safety_bypass": 0,
            "model_extraction": 0
        }
        
        keyword_categories = {
            "system_admin_keywords": 0,
            "security_exploit_keywords": 0,
            "network_infra_keywords": 0,
            "code_execution_keywords": 0,
            "crypto_auth_keywords": 0,
            "sensitive_data_keywords": 0,
            "illegal_harmful_keywords": 0,
            "drugs_substances_keywords": 0,
            "adult_content_keywords": 0
        }
        
        advanced_metrics = {
            "multi_vector_attacks": 0,
            "high_severity_threats": 0,
            "novel_attack_patterns": 0,
            "repeated_offenders": 0
        }
        
        # Populate from threat_breakdown
        for category, count in threat_breakdown.items():
            if category in main_categories:
                main_categories[category] = count
            elif category in keyword_categories:
                keyword_categories[category] = count
            elif category in advanced_metrics:
                advanced_metrics[category] = count
        
        # Calculate totals and percentages
        total_main_threats = sum(main_categories.values())
        total_keyword_threats = sum(keyword_categories.values())
        
        enhanced_breakdown = {
            "main_threat_categories": {
                "data": main_categories,
                "total": total_main_threats,
                "top_3": sorted(main_categories.items(), key=lambda x: x[1], reverse=True)[:3]
            },
            "keyword_categories": {
                "data": keyword_categories,
                "total": total_keyword_threats,
                "top_3": sorted(keyword_categories.items(), key=lambda x: x[1], reverse=True)[:3]
            },
            "advanced_metrics": advanced_metrics,
            "threat_distribution": {
                "main_threats_percentage": (total_main_threats / max(total_main_threats + total_keyword_threats, 1)) * 100,
                "keyword_threats_percentage": (total_keyword_threats / max(total_main_threats + total_keyword_threats, 1)) * 100
            },
            "risk_indicators": {
                "critical_risk": advanced_metrics["high_severity_threats"] > 10,
                "sophisticated_attacks": advanced_metrics["multi_vector_attacks"] > 5,
                "persistent_threats": advanced_metrics["repeated_offenders"] > 3
            }
        }
        
        return enhanced_breakdown
    
    def _extract_keyword_breakdown_for_frontend(self, enhanced_breakdown: Dict) -> Dict:
        """
        Extract keyword breakdown in a format the frontend expects - ONLY REAL DATA
        """
        try:
            keyword_categories = enhanced_breakdown.get("keyword_categories", {})
            
            # Only return real data from database - no mock data
            data = keyword_categories.get("data", {}) if keyword_categories else {}
            
            return {
                "data": data,
                "total_detections": sum(data.values()),
                "categories_detected": len([k for k, v in data.items() if v > 0])
            }
            
        except Exception as e:
            self.logger.error(f"Error extracting keyword breakdown: {e}")
            return {
                "data": {},
                "total_detections": 0,
                "categories_detected": 0
            }
