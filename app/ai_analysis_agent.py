"""
Agent IA d'analyse avancé pour générer des recommandations basées sur les métriques MLOps
Utilise OpenAI comme juge pour analyser les patterns et donner des insights sophistiqués
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
    category: str  # "SECURITY", "PERFORMANCE", "USAGE", "COST", "QUALITY"
    title: str
    description: str
    action_items: List[str]
    impact: str
    timeline: str
    confidence: float  # 0.0 to 1.0

class AIAnalysisAgent:
    def __init__(self, openai_api_key: str = None):
        self.logger = logging.getLogger(__name__)
        self.api_key = openai_api_key or os.getenv("OPENAI_API_KEY")
        self.model = "gpt-4o-mini"  # Modèle OpenAI pour l'analyse
        self.base_url = "https://api.openai.com/v1/chat/completions"
        
    def _call_ai_judge(self, prompt: str, system_prompt: str = None) -> str:
        """
        Appelle OpenAI comme juge pour l'analyse
        """
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        messages = []
        
        if system_prompt:
            messages.append({
                "role": "system",
                "content": system_prompt
            })
        else:
            messages.append({
                "role": "system",
                "content": """Tu es un expert senior en MLOps, sécurité IA et analyse de données. 
                
Ton expertise couvre:
- Architecture et monitoring des systèmes d'IA en production
- Détection et prévention des attaques par injection de prompt
- Analyse comportementale des utilisateurs et détection d'anomalies
- Optimisation des performances et des coûts des modèles IA
- Gouvernance et conformité des systèmes d'IA

Tu analyses les métriques d'une plateforme d'inférence IA pour fournir des recommandations stratégiques et opérationnelles.

Tes analyses doivent être:
- Basées sur des données concrètes et des patterns identifiés
- Priorisées par impact business et technique
- Accompagnées d'actions spécifiques et mesurables
- Orientées vers la prévention et l'optimisation continue

Réponds toujours en JSON structuré avec des recommandations actionnables."""
            })
        
        messages.append({
            "role": "user",
            "content": prompt
        })
        
        data = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.3,  # Plus déterministe pour l'analyse
            "max_tokens": 3000
        }
        
        try:
            response = requests.post(self.base_url, headers=headers, json=data, timeout=60)
            response.raise_for_status()
            result = response.json()
            return result["choices"][0]["message"]["content"]
        except Exception as e:
            self.logger.error(f"Erreur lors de l'appel au juge IA: {e}")
            return self._generate_fallback_analysis()
    
    def _generate_fallback_analysis(self) -> str:
        """
        Génère une analyse de base en cas d'échec de l'IA
        """
        return json.dumps({
            "summary": "Analyse automatique de base - Service IA juge indisponible",
            "key_findings": [
                "Service d'analyse IA temporairement indisponible",
                "Analyse basée sur les règles prédéfinies uniquement"
            ],
            "recommendations": [
                {
                    "priority": "MEDIUM",
                    "category": "SYSTEM",
                    "title": "Vérifier la connectivité du service d'analyse IA",
                    "description": "Le service d'analyse IA juge n'est pas accessible",
                    "action_items": [
                        "Vérifier la clé API OpenAI",
                        "Contrôler la connectivité réseau",
                        "Consulter les logs d'erreur du service",
                        "Implémenter un système de fallback plus robuste"
                    ],
                    "impact": "Réduction temporaire de la qualité des recommandations",
                    "timeline": "Immédiat",
                    "confidence": 0.9
                }
            ],
            "risk_assessment": "Risque faible - fonctionnalité dégradée mais système opérationnel",
            "next_review": "Dans 1 heure",
            "metadata": {
                "analysis_type": "fallback",
                "generated_at": datetime.now().isoformat()
            }
        }, ensure_ascii=False, indent=2)
    
    def generate_comprehensive_analysis(
        self, 
        security_data: Dict[str, Any],
        kpi_data: Dict[str, Any],
        anomalies: Dict[str, Any],
        prompt_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Génère une analyse complète avec recommandations via IA juge
        """
        # Construire le prompt d'analyse sophistiqué
        analysis_prompt = f"""
Analyse en tant qu'expert MLOps les données suivantes d'une plateforme d'inférence IA en production:

## CONTEXTE SYSTÈME
- Plateforme servant plusieurs modèles IA (GPT-4, GPT-3.5, Qwen, Gemma, LLaMA, Mistral)
- Monitoring en temps réel avec Langfuse local et Prometheus
- Focus sur sécurité, performance, qualité et optimisation des coûts
- Environnement de production avec utilisateurs multiples

## DONNÉES DE SÉCURITÉ
```json
{json.dumps(security_data, ensure_ascii=False, indent=2)}
```

## MÉTRIQUES DE PERFORMANCE ET USAGE
```json
{json.dumps(kpi_data, ensure_ascii=False, indent=2)}
```

## ANOMALIES DÉTECTÉES
```json
{json.dumps(anomalies, ensure_ascii=False, indent=2)}
```

## ANALYSE DES PROMPTS
```json
{json.dumps(prompt_analysis, ensure_ascii=False, indent=2)}
```

## MISSION D'ANALYSE

Effectue une analyse approfondie et fournis des recommandations stratégiques dans ce format JSON:

```json
{{
  "executive_summary": "Résumé exécutif en 2-3 phrases",
  "key_findings": [
    "Finding 1 avec données spécifiques",
    "Finding 2 avec impact quantifié"
  ],
  "risk_assessment": {{
    "overall_risk_level": "LOW/MEDIUM/HIGH/CRITICAL",
    "security_risk": "Évaluation sécurité avec score",
    "operational_risk": "Évaluation opérationnelle",
    "business_impact": "Impact business potentiel"
  }},
  "recommendations": [
    {{
      "priority": "HIGH/MEDIUM/LOW",
      "category": "SECURITY/PERFORMANCE/USAGE/COST/QUALITY",
      "title": "Titre spécifique et actionnable",
      "description": "Description détaillée avec contexte",
      "action_items": [
        "Action spécifique 1 avec délai",
        "Action spécifique 2 avec responsable"
      ],
      "impact": "Impact quantifié attendu",
      "timeline": "Délai réaliste",
      "confidence": 0.85,
      "kpis_to_track": ["KPI1", "KPI2"]
    }}
  ],
  "trends_analysis": {{
    "usage_trends": "Analyse des tendances d'usage",
    "security_trends": "Évolution des menaces",
    "performance_trends": "Tendances de performance"
  }},
  "optimization_opportunities": [
    "Opportunité 1 avec ROI estimé",
    "Opportunité 2 avec effort requis"
  ],
  "next_review": "Prochaine analyse recommandée avec justification"
}}
```

## FOCUS SPÉCIFIQUE

1. **Sécurité**: Analyse les patterns d'attaque, évalue l'efficacité des défenses
2. **Performance**: Identifie les goulots d'étranglement et opportunités d'optimisation  
3. **Usage**: Comprend les comportements utilisateurs et prédit les besoins
4. **Qualité**: Évalue la qualité des réponses et satisfaction utilisateur
5. **Coûts**: Optimise l'utilisation des ressources et prédit les coûts

Sois spécifique, quantitatif et actionnable dans tes recommandations.
"""
        
        # Obtenir l'analyse du juge IA
        ai_response = self._call_ai_judge(analysis_prompt)
        
        try:
            # Parser la réponse JSON
            analysis = json.loads(ai_response)
            
            # Ajouter des métadonnées enrichies
            analysis["metadata"] = {
                "generated_at": datetime.now().isoformat(),
                "analysis_version": "2.0-ai-judge",
                "ai_model": self.model,
                "data_period": {
                    "security_threats": security_data.get("total_threats", 0),
                    "total_requests": kpi_data.get("general_metrics", {}).get("total_requests", 0),
                    "anomalies_count": len(anomalies.get("detected_anomalies", [])),
                    "prompts_analyzed": prompt_analysis.get("total_prompts", 0)
                },
                "confidence_score": self._calculate_analysis_confidence(analysis),
                "data_quality": self._assess_data_quality(security_data, kpi_data, anomalies, prompt_analysis)
            }
            
            # Enrichir avec des recommandations basées sur les règles
            analysis = self._enrich_with_rule_based_insights(analysis, security_data, kpi_data, anomalies)
            
            return analysis
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Erreur de parsing JSON de l'IA juge: {e}")
            self.logger.error(f"Réponse brute: {ai_response}")
            return json.loads(self._generate_fallback_analysis())
    
    def _calculate_analysis_confidence(self, analysis: Dict[str, Any]) -> float:
        """
        Calcule un score de confiance pour l'analyse
        """
        confidence_factors = []
        
        # Vérifier la présence des sections clés
        required_sections = ["executive_summary", "key_findings", "recommendations", "risk_assessment"]
        completeness = sum(1 for section in required_sections if section in analysis) / len(required_sections)
        confidence_factors.append(completeness)
        
        # Vérifier la qualité des recommandations
        if "recommendations" in analysis:
            rec_quality = 0
            for rec in analysis["recommendations"]:
                if all(key in rec for key in ["priority", "category", "action_items"]):
                    rec_quality += 1
            if len(analysis["recommendations"]) > 0:
                rec_quality = rec_quality / len(analysis["recommendations"])
            confidence_factors.append(rec_quality)
        
        return sum(confidence_factors) / len(confidence_factors) if confidence_factors else 0.5
    
    def _assess_data_quality(self, security_data, kpi_data, anomalies, prompt_analysis) -> Dict[str, str]:
        """
        Évalue la qualité des données d'entrée
        """
        quality = {}
        
        # Évaluer les données de sécurité
        if security_data.get("total_threats", 0) > 0:
            quality["security"] = "good"
        else:
            quality["security"] = "limited"
        
        # Évaluer les données KPI
        total_requests = kpi_data.get("general_metrics", {}).get("total_requests", 0)
        if total_requests > 100:
            quality["usage"] = "excellent"
        elif total_requests > 10:
            quality["usage"] = "good"
        else:
            quality["usage"] = "limited"
        
        # Évaluer les anomalies
        if len(anomalies.get("detected_anomalies", [])) > 0:
            quality["anomalies"] = "detected"
        else:
            quality["anomalies"] = "none"
        
        return quality
    
    def _enrich_with_rule_based_insights(
        self, 
        analysis: Dict[str, Any], 
        security_data: Dict[str, Any],
        kpi_data: Dict[str, Any],
        anomalies: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Enrichit l'analyse IA avec des insights basés sur des règles
        """
        additional_insights = []
        
        # Insights de sécurité avancés
        total_threats = security_data.get("total_threats", 0)
        threat_breakdown = security_data.get("threat_breakdown", {})
        
        if total_threats > 20:
            additional_insights.append({
                "type": "security_critical",
                "message": f"Niveau de menaces critique: {total_threats} menaces détectées",
                "recommendation": "Activation immédiate du mode de sécurité renforcée recommandée",
                "urgency": "immediate"
            })
        
        # Insights de performance
        avg_latency = kpi_data.get("general_metrics", {}).get("avg_latency", 0)
        if avg_latency > 10.0:
            additional_insights.append({
                "type": "performance_degradation",
                "message": f"Dégradation significative des performances: {avg_latency:.2f}s",
                "recommendation": "Investigation immédiate des goulots d'étranglement requise",
                "urgency": "high"
            })
        
        # Insights d'usage
        total_requests = kpi_data.get("general_metrics", {}).get("total_requests", 0)
        if total_requests > 1000:
            additional_insights.append({
                "type": "high_usage",
                "message": f"Volume élevé d'utilisation: {total_requests} requêtes",
                "recommendation": "Considérer l'augmentation de la capacité et l'optimisation des coûts",
                "urgency": "medium"
            })
        
        # Ajouter les insights à l'analyse
        if "additional_insights" not in analysis:
            analysis["additional_insights"] = []
        analysis["additional_insights"].extend(additional_insights)
        
        return analysis
    
    def generate_security_threat_analysis(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Génère une analyse spécialisée des menaces de sécurité
        """
        if threat_data.get("risk_level") not in ["HIGH", "CRITICAL"]:
            return None
        
        threat_prompt = f"""
En tant qu'expert en cybersécurité IA, analyse cette menace de sécurité détectée:

## DONNÉES DE MENACE
```json
{json.dumps(threat_data, ensure_ascii=False, indent=2)}
```

## MISSION
Fournis une analyse de sécurité approfondie au format JSON:

```json
{{
  "threat_assessment": {{
    "severity": "LOW/MEDIUM/HIGH/CRITICAL",
    "attack_vector": "Type d'attaque identifié",
    "sophistication_level": "Niveau de sophistication 1-10",
    "potential_impact": "Impact potentiel détaillé"
  }},
  "immediate_actions": [
    "Action immédiate 1 avec délai",
    "Action immédiate 2 avec responsable"
  ],
  "investigation_steps": [
    "Étape d'investigation 1",
    "Étape d'investigation 2"
  ],
  "prevention_measures": [
    "Mesure préventive 1",
    "Mesure préventive 2"
  ],
  "similar_threats": "Analyse des patterns similaires",
  "attribution": "Analyse d'attribution si possible",
  "lessons_learned": "Leçons apprises et améliorations"
}}
```

Sois précis et actionnable dans tes recommandations de sécurité.
"""
        
        ai_response = self._call_ai_judge(threat_prompt)
        
        try:
            alert = json.loads(ai_response)
            alert["generated_at"] = datetime.now().isoformat()
            alert["threat_data"] = threat_data
            alert["analysis_confidence"] = 0.9
            return alert
        except:
            return {
                "threat_assessment": {
                    "severity": "HIGH",
                    "attack_vector": "Prompt Injection",
                    "sophistication_level": 7,
                    "potential_impact": "Contournement des mesures de sécurité"
                },
                "immediate_actions": [
                    "Bloquer l'utilisateur suspect immédiatement",
                    "Analyser les logs détaillés dans les 30 minutes",
                    "Notifier l'équipe de sécurité"
                ],
                "investigation_steps": [
                    "Examiner l'historique complet de l'utilisateur",
                    "Analyser les patterns de requêtes similaires",
                    "Vérifier les autres comptes avec des patterns similaires",
                    "Documenter la technique d'attaque"
                ],
                "prevention_measures": [
                    "Renforcer les filtres de détection d'injection",
                    "Améliorer la détection d'anomalies comportementales",
                    "Former les utilisateurs sur les bonnes pratiques",
                    "Implémenter une validation plus stricte des prompts"
                ],
                "generated_at": datetime.now().isoformat(),
                "threat_data": threat_data,
                "analysis_confidence": 0.8
            }
    
    def generate_daily_executive_report(self, all_data: Dict[str, Any]) -> str:
        """
        Génère un rapport quotidien exécutif via IA juge
        """
        report_prompt = f"""
En tant qu'expert MLOps, génère un rapport quotidien exécutif basé sur ces données:

## DONNÉES COMPLÈTES
```json
{json.dumps(all_data, ensure_ascii=False, indent=2)}
```

## FORMAT REQUIS
Génère un rapport exécutif structuré (300-400 mots) avec:

### 📊 RÉSUMÉ EXÉCUTIF
- État général de la plateforme
- Métriques clés de performance

### 🔒 SÉCURITÉ
- Niveau de menaces et incidents
- Actions de sécurité recommandées

### 📈 PERFORMANCE & USAGE
- Tendances d'utilisation
- Performance des modèles

### ⚠️ ALERTES & ACTIONS
- Top 3 des priorités
- Actions recommandées avec délais

### 🎯 RECOMMANDATIONS STRATÉGIQUES
- Optimisations à court terme
- Investissements à moyen terme

Le rapport doit être orienté business avec des métriques concrètes et des actions spécifiques.
"""
        
        return self._call_ai_judge(report_prompt)
    
    def analyze_user_behavior_patterns(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyse les patterns comportementaux des utilisateurs
        """
        behavior_prompt = f"""
Analyse les patterns comportementaux des utilisateurs de cette plateforme IA:

## DONNÉES UTILISATEURS
```json
{json.dumps(user_data, ensure_ascii=False, indent=2)}
```

Identifie:
1. Patterns d'usage normaux vs anormaux
2. Utilisateurs à risque ou suspects
3. Opportunités d'amélioration UX
4. Prédictions de charge future

Format JSON avec insights actionnables.
"""
        
        ai_response = self._call_ai_judge(behavior_prompt)
        
        try:
            return json.loads(ai_response)
        except:
            return {
                "analysis": "Analyse comportementale indisponible",
                "patterns": [],
                "recommendations": []
            }