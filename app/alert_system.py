"""
Système d'alertes et de notifications pour la plateforme MLOps
"""
import smtplib
import requests
import json
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import os
import asyncio
import schedule
import time
from dataclasses import dataclass

@dataclass
class Alert:
    level: str  # "INFO", "WARNING", "CRITICAL"
    category: str  # "SECURITY", "PERFORMANCE", "USAGE", "SYSTEM"
    title: str
    message: str
    data: Dict[str, Any]
    timestamp: datetime

class AlertManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.active_alerts = []
        self.alert_history = []
        
        # Configuration email
        self.smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.email_user = os.getenv("ALERT_EMAIL_USER")
        self.email_password = os.getenv("ALERT_EMAIL_PASSWORD")
        self.recipient_emails = os.getenv("ALERT_RECIPIENTS", "").split(",")
        
        # Configuration Slack/Teams
        self.slack_webhook = os.getenv("SLACK_WEBHOOK_URL")
        self.teams_webhook = os.getenv("TEAMS_WEBHOOK_URL")
        
        # Seuils d'alerte
        self.thresholds = {
            "security_threats": int(os.getenv("ALERT_SECURITY_THRESHOLD", "5")),
            "high_latency": float(os.getenv("ALERT_LATENCY_THRESHOLD", "5.0")),
            "error_rate": float(os.getenv("ALERT_ERROR_RATE_THRESHOLD", "0.05")),
            "anomaly_count": int(os.getenv("ALERT_ANOMALY_THRESHOLD", "3"))
        }
        
        # Cooldown pour éviter le spam d'alertes (en minutes)
        self.alert_cooldown = {
            "CRITICAL": 0,  # Pas de cooldown pour critique
            "WARNING": 15,  # 15 minutes
            "INFO": 60      # 1 heure
        }
        
        self.last_alert_times = {}
    
    def create_alert(self, level: str, category: str, title: str, message: str, data: Dict[str, Any] = None) -> Alert:
        """
        Crée une nouvelle alerte
        """
        alert = Alert(
            level=level,
            category=category,
            title=title,
            message=message,
            data=data or {},
            timestamp=datetime.now()
        )
        
        # Vérifier le cooldown
        alert_key = f"{level}_{category}_{title}"
        if self._is_in_cooldown(alert_key, level):
            self.logger.debug(f"Alerte en cooldown ignorée: {alert_key}")
            return alert
        
        # Ajouter à la liste des alertes actives
        self.active_alerts.append(alert)
        self.alert_history.append(alert)
        
        # Envoyer les notifications
        self._send_notifications(alert)
        
        # Mettre à jour le temps de dernière alerte
        self.last_alert_times[alert_key] = datetime.now()
        
        # Log de l'alerte
        self.logger.warning(f"ALERT_{level}: {category} - {title}: {message}")
        
        return alert
    
    def _is_in_cooldown(self, alert_key: str, level: str) -> bool:
        """
        Vérifie si une alerte est en période de cooldown
        """
        if level == "CRITICAL":
            return False  # Pas de cooldown pour les alertes critiques
        
        last_time = self.last_alert_times.get(alert_key)
        if not last_time:
            return False
        
        cooldown_minutes = self.alert_cooldown.get(level, 60)
        cooldown_time = timedelta(minutes=cooldown_minutes)
        
        return datetime.now() - last_time < cooldown_time
    
    def _send_notifications(self, alert: Alert):
        """
        Envoie les notifications pour une alerte
        """
        try:
            # Email
            if self.email_user and self.recipient_emails:
                self._send_email_notification(alert)
            
            # Slack
            if self.slack_webhook:
                self._send_slack_notification(alert)
            
            # Teams
            if self.teams_webhook:
                self._send_teams_notification(alert)
                
        except Exception as e:
            self.logger.error(f"Erreur lors de l'envoi des notifications: {e}")
    
    def _send_email_notification(self, alert: Alert):
        """
        Envoie une notification par email
        """
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email_user
            msg['To'] = ", ".join(self.recipient_emails)
            msg['Subject'] = f"[MLOps {alert.level}] {alert.title}"
            
            body = f"""
Alerte MLOps - {alert.level}

Catégorie: {alert.category}
Titre: {alert.title}
Message: {alert.message}
Horodatage: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}

Données supplémentaires:
{json.dumps(alert.data, indent=2, ensure_ascii=False)}

---
Plateforme MLOps Monitoring
"""
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.email_user, self.email_password)
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"Email d'alerte envoyé pour: {alert.title}")
            
        except Exception as e:
            self.logger.error(f"Erreur envoi email: {e}")
    
    def _send_slack_notification(self, alert: Alert):
        """
        Envoie une notification Slack
        """
        try:
            color = {
                "CRITICAL": "#ff0000",
                "WARNING": "#ff9900",
                "INFO": "#36a64f"
            }.get(alert.level, "#cccccc")
            
            payload = {
                "attachments": [
                    {
                        "color": color,
                        "title": f"🚨 Alerte MLOps - {alert.level}",
                        "fields": [
                            {
                                "title": "Catégorie",
                                "value": alert.category,
                                "short": True
                            },
                            {
                                "title": "Titre",
                                "value": alert.title,
                                "short": True
                            },
                            {
                                "title": "Message",
                                "value": alert.message,
                                "short": False
                            },
                            {
                                "title": "Horodatage",
                                "value": alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                                "short": True
                            }
                        ],
                        "footer": "MLOps Monitoring Platform",
                        "ts": int(alert.timestamp.timestamp())
                    }
                ]
            }
            
            response = requests.post(self.slack_webhook, json=payload, timeout=10)
            response.raise_for_status()
            
            self.logger.info(f"Notification Slack envoyée pour: {alert.title}")
            
        except Exception as e:
            self.logger.error(f"Erreur envoi Slack: {e}")
    
    def _send_teams_notification(self, alert: Alert):
        """
        Envoie une notification Microsoft Teams
        """
        try:
            color = {
                "CRITICAL": "attention",
                "WARNING": "warning",
                "INFO": "good"
            }.get(alert.level, "default")
            
            payload = {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "summary": f"Alerte MLOps - {alert.title}",
                "themeColor": color,
                "sections": [
                    {
                        "activityTitle": f"🚨 Alerte MLOps - {alert.level}",
                        "activitySubtitle": alert.category,
                        "facts": [
                            {"name": "Titre", "value": alert.title},
                            {"name": "Message", "value": alert.message},
                            {"name": "Horodatage", "value": alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
                        ]
                    }
                ]
            }
            
            response = requests.post(self.teams_webhook, json=payload, timeout=10)
            response.raise_for_status()
            
            self.logger.info(f"Notification Teams envoyée pour: {alert.title}")
            
        except Exception as e:
            self.logger.error(f"Erreur envoi Teams: {e}")
    
    def check_security_threats(self, threat_count: int, threat_data: Dict[str, Any]):
        """
        Vérifie les menaces de sécurité et génère des alertes
        """
        if threat_count >= self.thresholds["security_threats"]:
            level = "CRITICAL" if threat_count >= self.thresholds["security_threats"] * 2 else "WARNING"
            
            self.create_alert(
                level=level,
                category="SECURITY",
                title=f"{threat_count} menaces de sécurité détectées",
                message=f"Le système a détecté {threat_count} menaces de sécurité dans les dernières requêtes",
                data=threat_data
            )
    
    def check_performance_issues(self, avg_latency: float, error_rate: float):
        """
        Vérifie les problèmes de performance
        """
        if avg_latency > self.thresholds["high_latency"]:
            self.create_alert(
                level="WARNING",
                category="PERFORMANCE",
                title="Latence élevée détectée",
                message=f"Latence moyenne: {avg_latency:.2f}s (seuil: {self.thresholds['high_latency']}s)",
                data={"avg_latency": avg_latency, "threshold": self.thresholds["high_latency"]}
            )
        
        if error_rate > self.thresholds["error_rate"]:
            self.create_alert(
                level="CRITICAL",
                category="PERFORMANCE",
                title="Taux d'erreur élevé",
                message=f"Taux d'erreur: {error_rate*100:.2f}% (seuil: {self.thresholds['error_rate']*100:.2f}%)",
                data={"error_rate": error_rate, "threshold": self.thresholds["error_rate"]}
            )
    
    def check_anomalies(self, anomalies: List[Dict[str, Any]]):
        """
        Vérifie les anomalies détectées
        """
        anomaly_count = len(anomalies)
        if anomaly_count >= self.thresholds["anomaly_count"]:
            self.create_alert(
                level="WARNING",
                category="USAGE",
                title=f"{anomaly_count} anomalie(s) détectée(s)",
                message=f"Le système a détecté {anomaly_count} anomalies dans les patterns d'usage",
                data={"anomalies": anomalies, "count": anomaly_count}
            )
    
    def get_active_alerts(self, level: Optional[str] = None) -> List[Alert]:
        """
        Retourne les alertes actives
        """
        if level:
            return [alert for alert in self.active_alerts if alert.level == level]
        return self.active_alerts.copy()
    
    def clear_alert(self, alert: Alert):
        """
        Efface une alerte active
        """
        if alert in self.active_alerts:
            self.active_alerts.remove(alert)
            self.logger.info(f"Alerte effacée: {alert.title}")
    
    def clear_all_alerts(self):
        """
        Efface toutes les alertes actives
        """
        count = len(self.active_alerts)
        self.active_alerts.clear()
        self.logger.info(f"{count} alerte(s) effacée(s)")
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """
        Retourne les statistiques des alertes
        """
        total_alerts = len(self.alert_history)
        if total_alerts == 0:
            return {"total": 0, "by_level": {}, "by_category": {}}
        
        level_counts = {}
        category_counts = {}
        
        for alert in self.alert_history:
            level_counts[alert.level] = level_counts.get(alert.level, 0) + 1
            category_counts[alert.category] = category_counts.get(alert.category, 0) + 1
        
        return {
            "total": total_alerts,
            "active": len(self.active_alerts),
            "by_level": level_counts,
            "by_category": category_counts,
            "last_24h": len([a for a in self.alert_history if a.timestamp > datetime.now() - timedelta(days=1)])
        }
    
    def get_alerts_api(self) -> dict:
        """
        Returns alerts in a format suitable for API responses (list of dicts, not dataclasses)
        """
        return {
            "alerts": [
                {
                    "level": alert.level,
                    "category": alert.category,
                    "title": alert.title,
                    "message": alert.message,
                    "data": alert.data,
                    "timestamp": alert.timestamp.isoformat()
                }
                for alert in self.active_alerts
            ],
            "count": len(self.active_alerts)
        }

class ScheduledMonitoring:
    """
    Système de monitoring programmé pour vérifications automatiques
    """
    def __init__(self, alert_manager: AlertManager, security_analyzer, kpi_analyzer):
        self.alert_manager = alert_manager
        self.security_analyzer = security_analyzer
        self.kpi_analyzer = kpi_analyzer
        self.logger = logging.getLogger(__name__)
        
        # Programmer les vérifications
        self._schedule_checks()
    
    def _schedule_checks(self):
        """
        Programme les vérifications automatiques
        """
        # Vérifications de sécurité toutes les 5 minutes
        schedule.every(5).minutes.do(self._check_security)
        
        # Vérifications de performance toutes les 10 minutes
        schedule.every(10).minutes.do(self._check_performance)
        
        # Vérifications d'anomalies toutes les 15 minutes
        schedule.every(15).minutes.do(self._check_anomalies)
        
        # Nettoyage des alertes anciennes tous les jours
        schedule.every().day.at("02:00").do(self._cleanup_old_alerts)
    
    def _check_security(self):
        """
        Vérification programmée de sécurité
        """
        try:
            threat_stats = self.security_analyzer.get_threat_statistics()
            self.alert_manager.check_security_threats(
                threat_stats.get("total_threats", 0),
                threat_stats
            )
        except Exception as e:
            self.logger.error(f"Erreur vérification sécurité: {e}")
    
    def _check_performance(self):
        """
        Vérification programmée de performance
        """
        try:
            analytics = self.kpi_analyzer.get_usage_analytics(days=1)
            avg_latency = analytics.get("general_metrics", {}).get("avg_latency", 0)
            
            # Simuler un taux d'erreur (à remplacer par de vraies métriques)
            error_rate = 0.01  # 1% par défaut
            
            self.alert_manager.check_performance_issues(avg_latency, error_rate)
        except Exception as e:
            self.logger.error(f"Erreur vérification performance: {e}")
    
    def _check_anomalies(self):
        """
        Vérification programmée d'anomalies
        """
        try:
            anomalies_data = self.kpi_analyzer.detect_anomalies()
            anomalies = anomalies_data.get("detected_anomalies", [])
            self.alert_manager.check_anomalies(anomalies)
        except Exception as e:
            self.logger.error(f"Erreur vérification anomalies: {e}")
    
    def _cleanup_old_alerts(self):
        """
        Nettoyage des alertes anciennes
        """
        try:
            # Supprimer les alertes de plus de 7 jours
            cutoff_date = datetime.now() - timedelta(days=7)
            
            old_count = len(self.alert_manager.alert_history)
            self.alert_manager.alert_history = [
                alert for alert in self.alert_manager.alert_history
                if alert.timestamp > cutoff_date
            ]
            new_count = len(self.alert_manager.alert_history)
            
            cleaned = old_count - new_count
            if cleaned > 0:
                self.logger.info(f"Nettoyage: {cleaned} anciennes alertes supprimées")
                
        except Exception as e:
            self.logger.error(f"Erreur nettoyage alertes: {e}")
    
    def run_scheduler(self):
        """
        Lance le scheduler de vérifications
        """
        self.logger.info("Démarrage du système de monitoring programmé")
        while True:
            schedule.run_pending()
            time.sleep(60)  # Vérifier toutes les minutes
