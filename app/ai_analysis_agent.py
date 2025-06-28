"""
Agent IA d'analyse pour générer des recommandations basées sur les métriques MLOps
"""
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import requests
from dataclasses import dataclass
import os

@dataclass
class Recommendation:
    priority: str  # "HIGH", "MEDIUM", "LOW"
    category: str  # "SECURITY", "PERFORMANCE", "USAGE", "COST"
    title: str
    description: str
    action_items: List[str]
    impact: str
    timeline: str

class AIAnalysisAgent:
    def __init__(self, openrouter_api_key: str = None):
        self.logger = logging.getLogger(__name__)
        self.api_key = openrouter_api_key or os.getenv("OPENROUTER_API_KEY")
        self.model = "deepseek/deepseek-r1-0528-qwen3-8b:free"
        self.base_url = "https://openrouter.ai/api/v1/chat/completions"
        
    def _call_ai_model(self, prompt: str) -> str:
        """
        Appelle le modèle IA pour l'analyse
        """
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": """Tu es un expert en MLOps et sécurité IA. Ton rôle est d'analyser les métriques et données d'usage d'une plateforme d'inférence IA pour fournir des recommandations concrètes et actionnables.

Tu dois analyser:
- Les patterns d'usage et performance
- Les menaces de sécurité détectées
- Les anomalies dans le trafic
- L'efficacité des modèles

Tes recommandations doivent être:
- Spécifiques et actionnables
- Priorisées par impact/urgence
- Accompagnées d'étapes concrètes
- Orientées business et technique

Réponds toujours en JSON avec cette structure:
{
  "summary": "Résumé exécutif",
  "key_findings": ["finding1", "finding2"],
  "recommendations": [
    {
      "priority": "HIGH/MEDIUM/LOW",
      "category": "SECURITY/PERFORMANCE/USAGE/COST",
      "title": "Titre de la recommandation",
      "description": "Description détaillée",
      "action_items": ["action1", "action2"],
      "impact": "Impact attendu",
      "timeline": "Délai suggéré"
    }
  ],
  "risk_assessment": "Évaluation des risques",
  "next_review": "Prochaine analyse recommandée"
}"""
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.7,
            "max_tokens": 2000
        }
        
        try:
            response = requests.post(self.base_url, headers=headers, json=data, timeout=30)
            response.raise_for_status()
            result = response.json()
            return result["choices"][0]["message"]["content"]
        except Exception as e:
            self.logger.error(f"Erreur lors de l'appel au modèle IA: {e}")
            return self._generate_fallback_analysis()
    
    def _generate_fallback_analysis(self) -> str:
        """
        Génère une analyse de base en cas d'échec de l'IA
        """
        return json.dumps({
            "summary": "Analyse automatique de base - Service IA indisponible",
            "key_findings": [
                "Service d'analyse IA temporairement indisponible",
                "Analyse basée sur les règles prédéfinies"
            ],
            "recommendations": [
                {
                    "priority": "MEDIUM",
                    "category": "PERFORMANCE",
                    "title": "Vérifier la connectivité du service d'analyse",
                    "description": "Le service d'analyse IA n'est pas accessible",
                    "action_items": [
                        "Vérifier la clé API",
                        "Contrôler la connectivité réseau",
                        "Consulter les logs d'erreur"
                    ],
                    "impact": "Réduction de la qualité des recommandations",
                    "timeline": "Immédiat"
                }
            ],
            "risk_assessment": "Risque faible - fonctionnalité dégradée",
            "next_review": "Dans 1 heure"
        }, ensure_ascii=False, indent=2)
    
    def generate_comprehensive_analysis(
        self, 
        security_data: Dict[str, Any],
        kpi_data: Dict[str, Any],
        anomalies: Dict[str, Any],
        prompt_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Génère une analyse complète avec recommandations
        """
        # Construire le prompt d'analyse
        analysis_prompt = f"""
Analyse les données suivantes d'une plateforme MLOps d'inférence IA:

## DONNÉES DE SÉCURITÉ:
{json.dumps(security_data, ensure_ascii=False, indent=2)}

## MÉTRIQUES KPI:
{json.dumps(kpi_data, ensure_ascii=False, indent=2)}

## ANOMALIES DÉTECTÉES:
{json.dumps(anomalies, ensure_ascii=False, indent=2)}

## ANALYSE DES PROMPTS:
{json.dumps(prompt_analysis, ensure_ascii=False, indent=2)}

## CONTEXTE:
- Plateforme servant plusieurs modèles IA (GPT, Gemma, LLaMA, Mistral)
- Focus sur la sécurité, performance et optimisation des coûts
- Environnement de production avec monitoring Langfuse
- Besoin de recommandations actionnables pour les administrateurs

Fournis une analyse complète avec des recommandations priorisées.
"""
        
        # Obtenir l'analyse de l'IA
        ai_response = self._call_ai_model(analysis_prompt)
        
        try:
            # Parser la réponse JSON
            analysis = json.loads(ai_response)
            
            # Ajouter des métadonnées
            analysis["metadata"] = {
                "generated_at": datetime.now().isoformat(),
                "data_period": {
                    "security_threats": security_data.get("total_threats", 0),
                    "total_requests": kpi_data.get("general_metrics", {}).get("total_requests", 0),
                    "anomalies_count": len(anomalies.get("detected_anomalies", [])),
                    "prompts_analyzed": prompt_analysis.get("total_prompts", 0)
                },
                "analysis_version": "1.0"
            }
            
            # Ajouter des recommandations basées sur les règles si nécessaire
            analysis = self._add_rule_based_recommendations(analysis, security_data, kpi_data, anomalies)
            
            return analysis
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Erreur de parsing JSON: {e}")
            return json.loads(self._generate_fallback_analysis())
    
    def _add_rule_based_recommendations(
        self, 
        analysis: Dict[str, Any], 
        security_data: Dict[str, Any],
        kpi_data: Dict[str, Any],
        anomalies: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Ajoute des recommandations basées sur des règles prédéfinies
        """
        additional_recommendations = []
        
        # Règles de sécurité
        total_threats = security_data.get("total_threats", 0)
        if total_threats > 10:
            additional_recommendations.append({
                "priority": "HIGH",
                "category": "SECURITY",
                "title": "Niveau de menaces élevé détecté",
                "description": f"{total_threats} menaces de sécurité détectées récemment",
                "action_items": [
                    "Activer le mode de sécurité renforcée",
                    "Analyser les logs de sécurité détaillés",
                    "Considérer le blocage temporaire des utilisateurs suspects",
                    "Réviser les filtres de sécurité"
                ],
                "impact": "Réduction significative des risques de sécurité",
                "timeline": "Immédiat (dans les 2 heures)"
            })
        
        # Règles de performance
        avg_latency = kpi_data.get("general_metrics", {}).get("avg_latency", 0)
        if avg_latency > 5.0:  # 5 secondes
            additional_recommendations.append({
                "priority": "MEDIUM",
                "category": "PERFORMANCE",
                "title": "Latence élevée détectée",
                "description": f"Latence moyenne de {avg_latency:.2f}s dépasse le seuil recommandé",
                "action_items": [
                    "Analyser les goulots d'étranglement",
                    "Optimiser la configuration des modèles",
                    "Considérer la mise en cache des réponses",
                    "Évaluer l'ajout de ressources compute"
                ],
                "impact": "Amélioration de l'expérience utilisateur",
                "timeline": "1-2 semaines"
            })
        
        # Règles d'anomalies
        anomalies_count = len(anomalies.get("detected_anomalies", []))
        if anomalies_count > 0:
            additional_recommendations.append({
                "priority": "MEDIUM",
                "category": "USAGE",
                "title": f"{anomalies_count} anomalie(s) d'usage détectée(s)",
                "description": "Des patterns d'usage inhabituels ont été identifiés",
                "action_items": [
                    "Investiguer les anomalies détectées",
                    "Vérifier les comptes utilisateurs suspects",
                    "Ajuster les seuils d'alerte si nécessaire",
                    "Documenter les patterns normaux vs anormaux"
                ],
                "impact": "Meilleure compréhension des patterns d'usage",
                "timeline": "3-5 jours"
            })
        
        # Ajouter les recommandations supplémentaires
        if "recommendations" not in analysis:
            analysis["recommendations"] = []
        
        analysis["recommendations"].extend(additional_recommendations)
        
        return analysis
    
    def generate_security_alert(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Génère une alerte de sécurité spécialisée
        """
        if threat_data.get("risk_level") not in ["HIGH", "CRITICAL"]:
            return None
        
        alert_prompt = f"""
ALERTE SÉCURITÉ - Analyse immédiate requise:

{json.dumps(threat_data, ensure_ascii=False, indent=2)}

Génère une alerte de sécurité concise avec:
1. Évaluation de la menace
2. Actions immédiates recommandées
3. Mesures préventives à long terme

Format JSON requis:
{{
  "alert_level": "HIGH/CRITICAL",
  "threat_type": "type de menace",
  "immediate_actions": ["action1", "action2"],
  "investigation_steps": ["step1", "step2"],
  "prevention_measures": ["measure1", "measure2"]
}}
"""
        
        ai_response = self._call_ai_model(alert_prompt)
        
        try:
            alert = json.loads(ai_response)
            alert["generated_at"] = datetime.now().isoformat()
            alert["threat_data"] = threat_data
            return alert
        except:
            return {
                "alert_level": "HIGH",
                "threat_type": "Generic Security Threat",
                "immediate_actions": [
                    "Bloquer l'utilisateur suspect",
                    "Analyser les logs détaillés",
                    "Notifier l'équipe de sécurité"
                ],
                "investigation_steps": [
                    "Examiner l'historique de l'utilisateur",
                    "Analyser les patterns de requêtes",
                    "Vérifier les autres comptes similaires"
                ],
                "prevention_measures": [
                    "Renforcer les filtres de sécurité",
                    "Améliorer la détection d'anomalies",
                    "Former les utilisateurs sur les bonnes pratiques"
                ],
                "generated_at": datetime.now().isoformat(),
                "threat_data": threat_data
            }
    
    def generate_daily_report(self, all_data: Dict[str, Any]) -> str:
        """
        Génère un rapport quotidien en format texte
        """
        report_prompt = f"""
Génère un rapport quotidien exécutif basé sur ces données MLOps:

{json.dumps(all_data, ensure_ascii=False, indent=2)}

Le rapport doit être:
- Concis (200-300 mots)
- Orienté business
- Avec des métriques clés
- Des alertes prioritaires
- Des recommandations top 3

Format: Texte structuré avec sections claires.
"""
        
        return self._call_ai_model(report_prompt)
