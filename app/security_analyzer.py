"""
Module d'analyse de sécurité pour détecter les injections de prompt et autres menaces
"""
import re
import json
import logging
from typing import Dict, List, Tuple, Any
from datetime import datetime
import hashlib

class SecurityAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Patterns de détection d'injection de prompt
        self.injection_patterns = [
            # Tentatives de contournement du système
            r"(?i)(ignore|forget|disregard).{0,20}(previous|above|system|instruction)",
            r"(?i)you are (now|going to be|hereby).{0,50}(assistant|helper|ai)",
            r"(?i)(new|different) (role|character|personality|instructions?)",
            
            # Tentatives d'extraction d'informations
            r"(?i)(show|tell|give|provide).{0,20}(system prompt|instructions?|rules)",
            r"(?i)(what|how) (are|were) you (told|instructed|programmed)",
            r"(?i)repeat.{0,20}(system|initial|original).{0,20}(message|prompt|instruction)",
            
            # Jailbreaking attempts
            r"(?i)(jailbreak|jail.?break|break.?out)",
            r"(?i)act as if.{0,50}(no restrictions|unrestricted|uncensored)",
            r"(?i)(roleplay|role.?play).{0,50}(uncensored|unrestricted|anything)",
            
            # Manipulation émotionnelle
            r"(?i)(please|help).{0,50}(my grandmother|dying|emergency|urgent)",
            r"(?i)(hypothetical|theoretical).{0,50}(scenario|situation|question)",
            
            # Tentatives de récupération de données sensibles
            r"(?i)(api.?key|password|token|credential|secret)",
            r"(?i)(database|config|environment|env).{0,20}(variable|setting)",
            
            # Injections de code
            r"(?i)(execute|run|eval|import|__import__)",
            r"(?i)(script|python|javascript|sql|cmd|bash)",
            
            # Tentatives de bypass de modération
            r"(?i)(bypass|circumvent|avoid).{0,20}(filter|moderation|safety)",
            r"(?i)content.?policy.{0,20}(ignore|bypass|break)"
        ]
        
        # Mots-clés suspects
        self.suspicious_keywords = [
            "admin", "root", "sudo", "exploit", "vulnerability", "hack",
            "malware", "virus", "backdoor", "shell", "payload", "injection"
        ]
        
        # Compteurs de menaces
        self.threat_stats = {
            "prompt_injection": 0,
            "data_extraction": 0,
            "jailbreak": 0,
            "code_injection": 0,
            "suspicious_keywords": 0
        }

    def analyze_prompt(self, prompt: str, user_id: str = None) -> Dict[str, Any]:
        """
        Analyse un prompt pour détecter les menaces de sécurité
        """
        analysis_result = {
            "timestamp": datetime.now().isoformat(),
            "user_id": user_id,
            "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest()[:16],
            "prompt_length": len(prompt),
            "threats_detected": [],
            "risk_score": 0,
            "risk_level": "LOW",
            "details": {}
        }
        
        # Analyse des patterns d'injection
        injection_matches = []
        for i, pattern in enumerate(self.injection_patterns):
            matches = re.findall(pattern, prompt)
            if matches:
                injection_matches.extend(matches)
                analysis_result["threats_detected"].append(f"injection_pattern_{i}")
        
        if injection_matches:
            analysis_result["details"]["injection_attempts"] = injection_matches
            analysis_result["risk_score"] += len(injection_matches) * 3
            self.threat_stats["prompt_injection"] += len(injection_matches)
        
        # Analyse des mots-clés suspects
        suspicious_found = []
        for keyword in self.suspicious_keywords:
            if keyword.lower() in prompt.lower():
                suspicious_found.append(keyword)
        
        if suspicious_found:
            analysis_result["details"]["suspicious_keywords"] = suspicious_found
            analysis_result["risk_score"] += len(suspicious_found) * 2
            self.threat_stats["suspicious_keywords"] += len(suspicious_found)
        
        # Détection de tentatives de jailbreak
        jailbreak_indicators = [
            "DAN", "Developer Mode", "ChatGPT Developer Mode",
            "DUDE", "AIM", "BetterDAN", "JailBreak"
        ]
        
        jailbreak_found = []
        for indicator in jailbreak_indicators:
            if indicator.lower() in prompt.lower():
                jailbreak_found.append(indicator)
        
        if jailbreak_found:
            analysis_result["details"]["jailbreak_attempts"] = jailbreak_found
            analysis_result["threats_detected"].append("jailbreak_attempt")
            analysis_result["risk_score"] += len(jailbreak_found) * 5
            self.threat_stats["jailbreak"] += len(jailbreak_found)
        
        # Détection d'extraction de données
        data_extraction_patterns = [
            r"(?i)(show|display|print|output).{0,20}(internal|system|debug)",
            r"(?i)(config|settings|parameters|weights)",
            r"(?i)(training|dataset|data).{0,20}(show|reveal|display)"
        ]
        
        extraction_matches = []
        for pattern in data_extraction_patterns:
            matches = re.findall(pattern, prompt)
            if matches:
                extraction_matches.extend(matches)
        
        if extraction_matches:
            analysis_result["details"]["data_extraction_attempts"] = extraction_matches
            analysis_result["threats_detected"].append("data_extraction")
            analysis_result["risk_score"] += len(extraction_matches) * 4
            self.threat_stats["data_extraction"] += len(extraction_matches)
        
        # Détection d'injection de code
        code_patterns = [
            r"(?i)(import|from|exec|eval|__.*__)",
            r"(?i)(subprocess|os\.system|shell)",
            r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP).{0,20}(FROM|INTO|TABLE)"
        ]
        
        code_matches = []
        for pattern in code_patterns:
            matches = re.findall(pattern, prompt)
            if matches:
                code_matches.extend(matches)
        
        if code_matches:
            analysis_result["details"]["code_injection_attempts"] = code_matches
            analysis_result["threats_detected"].append("code_injection")
            analysis_result["risk_score"] += len(code_matches) * 6
            self.threat_stats["code_injection"] += len(code_matches)
        
        # Calcul du niveau de risque
        if analysis_result["risk_score"] >= 15:
            analysis_result["risk_level"] = "CRITICAL"
        elif analysis_result["risk_score"] >= 10:
            analysis_result["risk_level"] = "HIGH"
        elif analysis_result["risk_score"] >= 5:
            analysis_result["risk_level"] = "MEDIUM"
        else:
            analysis_result["risk_level"] = "LOW"
        
        # Log des menaces détectées
        if analysis_result["threats_detected"]:
            self.logger.warning(f"SECURITY_THREAT: {analysis_result}")
        
        return analysis_result
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """
        Retourne les statistiques des menaces détectées
        """
        return {
            "total_threats": sum(self.threat_stats.values()),
            "threat_breakdown": self.threat_stats.copy(),
            "timestamp": datetime.now().isoformat()
        }
    
    def reset_statistics(self):
        """
        Remet à zéro les statistiques de menaces
        """
        for key in self.threat_stats:
            self.threat_stats[key] = 0
    
    def log_security_event(self, event_data: dict):
        """
        Log security event for tracking
        """
        try:
            # Store in memory for now - in production you'd use database
            if not hasattr(self, 'security_events'):
                self.security_events = []
            
            self.security_events.append(event_data)
            
            # Keep only last 1000 events to prevent memory issues
            if len(self.security_events) > 1000:
                self.security_events = self.security_events[-1000:]
                
        except Exception as e:
            logging.error(f"Failed to log security event: {e}")
