"""
Dashboard de monitoring pour la plateforme MLOps
"""
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import json
import os
from datetime import datetime, timedelta
from typing import Dict, Any, List
import logging
import psycopg2
from psycopg2.extras import Json

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
        
        # Créer le dossier templates s'il n'existe pas
        os.makedirs("templates", exist_ok=True)
        os.makedirs("static", exist_ok=True)
        
        # Database connection setup
        self.db_conn = psycopg2.connect(
            dbname=os.getenv("POSTGRES_DB", "mlops"),
            user=os.getenv("POSTGRES_USER", "mlops"),
            password=os.getenv("POSTGRES_PASSWORD", "mlops"),
            host=os.getenv("POSTGRES_HOST", "mlops-postgres"),
            port=os.getenv("POSTGRES_PORT", "5432")
        )
        self.db_conn.autocommit = True
        self.db_cursor = self.db_conn.cursor()
        
        # Ajouter les routes du dashboard
        self._setup_routes()
        
    def _setup_routes(self):
        """
        Configure les routes du dashboard
        """
        # Monter les fichiers statiques
        self.app.mount("/static", StaticFiles(directory="static"), name="static")
        
        @self.app.get("/dashboard", response_class=HTMLResponse)
        async def dashboard_home(request: Request):
            return self.templates.TemplateResponse("dashboard.html", {"request": request})
        
        @self.app.get("/api/dashboard/overview")
        async def dashboard_overview():
            """
            API pour obtenir les données de vue d'ensemble
            """
            try:
                # Récupérer les métriques avec gestion d'erreur
                try:
                    security_stats = self.security_analyzer.get_threat_statistics()
                except Exception as e:
                    self.logger.warning(f"Erreur lors de la récupération des stats de sécurité: {e}")
                    security_stats = {"total_threats": 0, "threat_breakdown": {}}
                
                try:
                    usage_analytics = self.kpi_analyzer.get_usage_analytics(days=7)
                    if "error" in usage_analytics:
                        # Cas où il n'y a pas de données
                        usage_analytics = {
                            "general_metrics": {
                                "total_requests": 0,
                                "avg_latency": 0,
                                "unique_users": 0,
                                "avg_requests_per_day": 0
                            }
                        }
                except Exception as e:
                    self.logger.warning(f"Erreur lors de la récupération des analytics: {e}")
                    usage_analytics = {
                        "general_metrics": {
                            "total_requests": 0,
                            "avg_latency": 0,
                            "unique_users": 0,
                            "avg_requests_per_day": 0
                        }
                    }
                
                try:
                    anomalies = self.kpi_analyzer.detect_anomalies()
                except Exception as e:
                    self.logger.warning(f"Erreur lors de la détection d'anomalies: {e}")
                    anomalies = {"detected_anomalies": []}
                
                overview = {
                    "timestamp": datetime.now().isoformat(),
                    "security": {
                        "total_threats": security_stats.get("total_threats", 0),
                        "threat_level": "HIGH" if security_stats.get("total_threats", 0) > 10 else "MEDIUM" if security_stats.get("total_threats", 0) > 5 else "LOW",
                        "breakdown": security_stats.get("threat_breakdown", {})
                    },
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
                # Retourner une réponse par défaut plutôt que lever une exception
                default_overview = {
                    "timestamp": datetime.now().isoformat(),
                    "security": {
                        "total_threats": 0,
                        "threat_level": "LOW",
                        "breakdown": {}
                    },
                    "usage": {
                        "total_requests": 0,
                        "avg_latency": 0,
                        "unique_users": 0,
                        "requests_per_day": 0
                    },
                    "anomalies": {
                        "count": 0,
                        "types": []
                    }
                }
                return JSONResponse(content=default_overview)
        
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
            API pour les recommandations de l'IA
            """
            try:
                # Collecter toutes les données avec gestion d'erreur
                try:
                    security_data = self.security_analyzer.get_threat_statistics()
                except Exception as e:
                    self.logger.warning(f"Erreur sécurité: {e}")
                    security_data = {"total_threats": 0, "threat_breakdown": {}}
                
                try:
                    kpi_data = self.kpi_analyzer.get_usage_analytics(days=7)
                    if "error" in kpi_data:
                        kpi_data = {"general_metrics": {"total_requests": 0, "avg_latency": 0}}
                except Exception as e:
                    self.logger.warning(f"Erreur KPI: {e}")
                    kpi_data = {"general_metrics": {"total_requests": 0, "avg_latency": 0}}
                
                try:
                    anomalies = self.kpi_analyzer.detect_anomalies()
                except Exception as e:
                    self.logger.warning(f"Erreur anomalies: {e}")
                    anomalies = {"detected_anomalies": []}
                
                try:
                    prompt_analysis = self.kpi_analyzer.get_prompt_analysis()
                except Exception as e:
                    self.logger.warning(f"Erreur analyse prompt: {e}")
                    prompt_analysis = {"total_prompts": 0}
                
                # Générer les recommandations avec fallback
                try:
                    recommendations = self.ai_agent.generate_comprehensive_analysis(
                        security_data, kpi_data, anomalies, prompt_analysis
                    )
                    
                    # Vérifier que la structure est correcte
                    if not isinstance(recommendations, dict):
                        raise ValueError("Réponse de l'IA malformée")
                    
                    # S'assurer que les champs requis existent
                    if "recommendations" not in recommendations:
                        recommendations["recommendations"] = []
                    if "summary" not in recommendations:
                        recommendations["summary"] = "Aucune recommandation disponible pour le moment."
                    
                    return JSONResponse(content=recommendations)
                    
                except Exception as ai_error:
                    self.logger.error(f"Erreur lors de l'analyse IA: {ai_error}")
                    # Retourner des recommandations basiques basées sur les règles
                    fallback_recommendations = self._generate_fallback_recommendations(
                        security_data, kpi_data, anomalies
                    )
                    return JSONResponse(content=fallback_recommendations)
                
            except Exception as e:
                self.logger.error(f"Erreur dans dashboard_recommendations: {e}")
                # Retourner une structure minimale mais valide
                default_recommendations = {
                    "summary": "Système en cours d'initialisation. Revenez dans quelques minutes.",
                    "recommendations": [],
                    "metadata": {
                        "generated_at": datetime.now().isoformat(),
                        "status": "fallback"
                    }
                }
                return JSONResponse(content=default_recommendations)
        
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
                try:
                    security_stats = self.security_analyzer.get_threat_statistics()
                except Exception as e:
                    self.logger.error(f"Erreur get_threat_statistics: {e}")
                    security_stats = {"total_threats": 0}
                if security_stats.get("total_threats", 0) > 5:
                    alerts.append({
                        "type": "security",
                        "level": "warning" if security_stats["total_threats"] < 10 else "critical",
                        "message": f"{security_stats['total_threats']} menaces de sécurité détectées",
                        "timestamp": datetime.now().isoformat()
                    })
                # Vérifier les anomalies
                try:
                    anomalies = self.kpi_analyzer.detect_anomalies()
                except Exception as e:
                    self.logger.error(f"Erreur detect_anomalies: {e}")
                    anomalies = {"detected_anomalies": []}
                for anomaly in anomalies.get("detected_anomalies", []):
                    alerts.append({
                        "type": "anomaly",
                        "level": "warning",
                        "message": f"Anomalie détectée: {anomaly.get('type')}",
                        "timestamp": datetime.now().isoformat(),
                        "details": anomaly
                    })
                # Vérifier les performances
                try:
                    usage_analytics = self.kpi_analyzer.get_usage_analytics(days=1)
                except Exception as e:
                    self.logger.error(f"Erreur get_usage_analytics: {e}")
                    usage_analytics = {"general_metrics": {}}
                avg_latency = usage_analytics.get("general_metrics", {}).get("avg_latency", 0)
                if avg_latency > 5.0:
                    alerts.append({
                        "type": "performance",
                        "level": "warning",
                        "message": f"Latence élevée: {avg_latency:.2f}s",
                        "timestamp": datetime.now().isoformat()
                    })
                return JSONResponse(content={"alerts": alerts, "count": len(alerts)})
            except Exception as e:
                self.logger.error(f"Erreur dans dashboard_alerts: {e}")
                return JSONResponse(content={"alerts": [], "count": 0})
        
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
                # Collecter toutes les données
                all_data = {
                    "security": self.security_analyzer.get_threat_statistics(),
                    "usage": self.kpi_analyzer.get_usage_analytics(days=1),
                    "anomalies": self.kpi_analyzer.detect_anomalies(),
                    "prompts": self.kpi_analyzer.get_prompt_analysis()
                }
                
                # Générer le rapport
                report = self.ai_agent.generate_daily_report(all_data)
                
                return JSONResponse(content={
                    "report": report,
                    "generated_at": datetime.now().isoformat(),
                    "data_summary": {
                        "total_threats": all_data["security"].get("total_threats", 0),
                        "total_requests": all_data["usage"].get("general_metrics", {}).get("total_requests", 0),
                        "anomalies_count": len(all_data["anomalies"].get("detected_anomalies", [])),
                        "prompts_analyzed": all_data["prompts"].get("total_prompts", 0)
                    }
                })
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
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
                import ipaddress
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
                        alert = self.ai_agent.generate_security_alert(security_analysis)
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
    
    def _generate_fallback_recommendations(self, security_data, kpi_data, anomalies):
        """
        Génère des recommandations de base basées sur des règles simples
        """
        recommendations = []
        
        total_threats = security_data.get("total_threats", 0)
        avg_latency = kpi_data.get("general_metrics", {}).get("avg_latency", 0)
        total_requests = kpi_data.get("general_metrics", {}).get("total_requests", 0)
        anomalies_count = len(anomalies.get("detected_anomalies", []))
        
        # Recommandations basées sur la sécurité
        if total_threats > 10:
            recommendations.append({
                "priority": "HIGH",
                "category": "SECURITY",
                "title": "Niveau de menaces critique",
                "description": f"{total_threats} menaces de sécurité détectées",
                "action_items": [
                    "Activer le mode de sécurité renforcée",
                    "Examiner les logs de sécurité",
                    "Considérer le blocage des utilisateurs suspects"
                ],
                "impact": "Réduction des risques de sécurité",
                "timeline": "Immédiat"
            })
        elif total_threats > 5:
            recommendations.append({
                "priority": "MEDIUM",
                "category": "SECURITY",
                "title": "Surveillance sécurité recommandée",
                "description": f"{total_threats} menaces détectées",
                "action_items": [
                    "Surveiller l'évolution des menaces",
                    "Réviser les filtres de sécurité"
                ],
                "impact": "Prévention des incidents",
                "timeline": "24 heures"
            })
        
        # Recommandations basées sur la performance
        if avg_latency > 5.0:
            recommendations.append({
                "priority": "MEDIUM",
                "category": "PERFORMANCE",
                "title": "Latence élevée détectée",
                "description": f"Latence moyenne: {avg_latency:.2f}s",
                "action_items": [
                    "Analyser les goulots d'étranglement",
                    "Optimiser la configuration des modèles",
                    "Considérer la mise en cache"
                ],
                "impact": "Amélioration de l'expérience utilisateur",
                "timeline": "1-2 semaines"
            })
        
        # Recommandations basées on les anomalies
        if anomalies_count > 0:
            recommendations.append({
                "priority": "MEDIUM",
                "category": "MONITORING",
                "title": f"{anomalies_count} anomalie(s) détectée(s)",
                "description": "Patterns d'usage inhabituels identifiés",
                "action_items": [
                    "Investiguer les anomalies",
                    "Vérifier les comptes utilisateurs",
                    "Ajuster les seuils d'alerte"
                ],
                "impact": "Meilleure compréhension des patterns",
                "timeline": "3-5 jours"
            })
        
        # Si pas d'anomalies particulières, recommandations générales
        if not recommendations:
            recommendations.append({
                "priority": "LOW",
                "category": "OPTIMIZATION",
                "title": "Système fonctionnant normalement",
                "description": "Aucun problème critique détecté",
                "action_items": [
                    "Continuer la surveillance",
                    "Réviser les métriques mensuelles",
                    "Planifier les optimisations futures"
                ],
                "impact": "Maintenance préventive",
                "timeline": "Mensuel"
            })
        
        summary = f"Analyse de {total_requests} requêtes. "
        if total_threats > 0:
            summary += f"{total_threats} menaces détectées. "
        if avg_latency > 2.0:
            summary += f"Latence: {avg_latency:.2f}s. "
        if anomalies_count > 0:
            summary += f"{anomalies_count} anomalies identifiées."
        
        return {
            "summary": summary,
            "recommendations": recommendations,
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "data_period": {
                    "security_threats": total_threats,
                    "total_requests": total_requests,
                    "anomalies_count": anomalies_count
                },
                "analysis_version": "fallback-1.0"
            }
        }
