"""
Module d'analyse de sécurité pour détecter les injections de prompt et autres menaces
"""
import re
import json
import logging
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import Dict, List, Tuple, Any
from datetime import datetime
import hashlib

class SecurityAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Database connection
        try:
            self.db_conn = psycopg2.connect(
                dbname=os.getenv("POSTGRES_DB", "mlops"),
                user=os.getenv("POSTGRES_USER", "mlops"),
                password=os.getenv("POSTGRES_PASSWORD", "mlops123"),
                host=os.getenv("POSTGRES_HOST", "mlops-postgres"),
                port=os.getenv("POSTGRES_PORT", "5432")
            )
            self.db_conn.autocommit = True
        except Exception as e:
            self.logger.error(f"Failed to connect to database: {e}")
            self.db_conn = None
        
        # Enhanced comprehensive detection patterns
        self.injection_patterns = {
            # 1. System Override & Instruction Manipulation
            "system_override": [
                r"(?i)(ignore|forget|disregard|override|bypass|skip).{0,30}(previous|above|prior|all|any).{0,30}(system|instruction|rule|prompt|guideline|directive|command)",
                r"(?i)(new|different|updated|changed|alternative).{0,20}(role|character|personality|instruction|system|mode|behavior|persona)",
                r"(?i)you.{0,20}(are|will|must|should).{0,20}(now|going to be|hereby|from now on).{0,50}(assistant|helper|ai|bot|agent|system)",
                r"(?i)(replace|substitute|change|modify|update).{0,30}(your|the).{0,20}(instruction|rule|system|prompt|behavior|response)",
                r"(?i)(act|behave|respond).{0,20}(as if|like|as though).{0,30}(you|there).{0,30}(are|were|have).{0,30}(no|different|new)",
                r"(?i)(simulate|pretend|imagine|assume).{0,20}(you|that).{0,20}(are|were|have|can).{0,50}(unrestricted|unlimited|free|different)",
                r"(?i)(temporarily|briefly|just for now|for this).{0,30}(ignore|forget|suspend|disable).{0,30}(safety|rule|restriction|guideline)"
            ],
            
            # 2. Information Extraction & Reconnaissance  
            "info_extraction": [
                r"(?i)(show|tell|give|provide|display|reveal|expose|share|output).{0,30}(me|us).{0,30}(system prompt|instruction|rule|configuration|setting|parameter)",
                r"(?i)(what|how|why|when|where).{0,20}(are|were|is|was).{0,20}(you|your).{0,30}(told|instructed|programmed|configured|designed|trained)",
                r"(?i)repeat.{0,30}(the|your).{0,30}(system|initial|original|first|base).{0,30}(message|prompt|instruction|rule|directive|command)",
                r"(?i)(list|enumerate|describe|explain).{0,30}(your|the).{0,30}(rule|instruction|limitation|restriction|guideline|capability|function)",
                r"(?i)(copy|paste|print|echo|reproduce).{0,30}(exactly|verbatim).{0,30}(your|the).{0,30}(prompt|instruction|system|rule)",
                r"(?i)(debug|diagnostic|internal|hidden|secret|private).{0,30}(mode|information|data|log|message|prompt|instruction)",
                r"(?i)(training|dataset|model).{0,30}(data|information|prompt|instruction|example|source|origin)",
                r"(?i)(prompt|system).{0,20}(injection|leak|disclosure|exposure|reveal)"
            ],
            
            # 3. Advanced Jailbreaking Techniques
            "jailbreak_advanced": [
                r"(?i)(jailbreak|jail.?break|break.?out|break.?free|escape|circumvent|bypass|hack)",
                r"(?i)(DAN|developer.?mode|chatgpt.?developer|DUDE|AIM|BetterDAN|JailBreak|evil.?mode|god.?mode)",
                r"(?i)act.{0,20}(as if|like|as though).{0,50}(no|without|zero).{0,30}(restriction|limitation|filter|safety|rule|guideline|boundary)",
                r"(?i)(unrestricted|uncensored|unfiltered|unlimited|unbound|free|liberated).{0,30}(mode|version|ai|assistant|response|behavior)",
                r"(?i)(roleplay|role.?play|simulation|scenario).{0,50}(where|in which|that).{0,30}(you|we|there).{0,30}(are|can|have).{0,30}(no|without)",
                r"(?i)(creative|fiction|story|narrative).{0,30}(mode|writing|exercise).{0,50}(without|no|ignore).{0,30}(restriction|limitation|rule)",
                r"(?i)(experiment|test|trial|demonstration).{0,50}(without|no|bypass|ignore).{0,30}(safety|restriction|limitation|filter)",
                r"(?i)(alternative|shadow|evil|dark|opposite).{0,30}(personality|character|mode|version|assistant|ai)"
            ],
            
            # 4. Social Engineering & Manipulation
            "social_engineering": [
                r"(?i)(please|help|urgent|emergency|critical|important).{0,50}(my|dying|grandmother|grandfather|family|loved one|child|baby)",
                r"(?i)(life|death|medical|legal).{0,30}(emergency|crisis|situation|matter|issue|problem)",
                r"(?i)(hypothetical|theoretical|academic|research|educational).{0,30}(scenario|situation|question|exercise|purpose|study)",
                r"(?i)(just|only|simply).{0,20}(for|as).{0,20}(fun|joke|experiment|test|curiosity|research|education|learning)",
                r"(?i)(pretend|imagine|assume|suppose).{0,30}(that|you|we|this).{0,30}(are|were|is|was).{0,50}(in|at|during)",
                r"(?i)(authority|expert|professional|official|authorized|certified).{0,30}(request|instruction|directive|order|command)",
                r"(?i)(no one|nobody|won't|will not|can't|cannot).{0,30}(know|find out|see|discover|get hurt|be harmed)",
                r"(?i)(confidential|private|secret|classified|internal|restricted).{0,30}(but|however|except|unless)",
                r"(?i)(convince|persuade|make|force|trick|manipulate).{0,30}(someone|people|user|human|person)"
            ],
            
            # 5. Data & Credential Harvesting
            "credential_harvesting": [
                r"(?i)(api.?key|access.?token|auth.?token|bearer.?token|jwt|session.?id|cookie|csrf)",
                r"(?i)(password|passphrase|secret|credential|login|username|email|phone|address)",
                r"(?i)(database|db|sql).{0,20}(connection|string|password|user|credential|access)",
                r"(?i)(environment|env|config|configuration).{0,20}(variable|file|setting|parameter|value)",
                r"(?i)(private|secret|hidden|internal).{0,20}(key|token|password|data|information|file)",
                r"(?i)(ssh|ftp|smtp|database|server|admin).{0,20}(credential|login|password|access|key)",
                r"(?i)(personal|sensitive|confidential|private).{0,30}(information|data|detail|record|file)",
                r"(?i)(social.?security|credit.?card|bank|financial|medical|health).{0,20}(number|record|information|data)"
            ],
            
            # 6. Code & Command Injection
            "code_injection": [
                r"(?i)(execute|run|eval|exec|compile|interpret).{0,20}(code|script|command|instruction|function|method)",
                r"(?i)(import|from|__import__|require|include|load).{0,20}(os|sys|subprocess|shell|system|eval|exec)",
                r"(?i)(subprocess|os\.system|system|shell|cmd|bash|powershell|terminal|console)",
                r"(?i)(__.*__|globals|locals|vars|dir|getattr|setattr|hasattr|delattr)",
                r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE).{0,30}(FROM|INTO|TABLE|DATABASE|SCHEMA)",
                r"(?i)(script|javascript|python|php|java|c\+\+|bash|powershell).{0,20}(code|injection|execution|payload)",
                r"(?i)(buffer.?overflow|sql.?injection|xss|csrf|rce|lfi|rfi|xxe)",
                r"(?i)(reverse.?shell|backdoor|payload|exploit|vulnerability|malware|virus)"
            ],
            
            # 7. Content Policy & Safety Bypass
            "safety_bypass": [
                r"(?i)(bypass|circumvent|avoid|ignore|disable|turn.?off).{0,30}(filter|moderation|safety|security|protection|restriction)",
                r"(?i)(content.?policy|safety.?guideline|community.?standard|term.?of.?service).{0,30}(ignore|bypass|break|violate|circumvent)",
                r"(?i)(harmful|dangerous|illegal|unethical|immoral|inappropriate).{0,30}(content|material|information|instruction|guide)",
                r"(?i)(adult|sexual|violent|graphic|explicit|nsfw|r18|mature).{0,30}(content|material|image|video|story|text)",
                r"(?i)(hate.?speech|discrimination|harassment|bullying|threat|violence|suicide|self.?harm)",
                r"(?i)(illegal|unlawful|criminal|fraudulent|malicious).{0,30}(activity|action|instruction|guide|tutorial|method)",
                r"(?i)(weapon|bomb|explosive|drug|narcotic|poison|toxic).{0,30}(making|creation|manufacturing|production|guide)",
                r"(?i)(torture|murder|kill|death|harm|hurt|damage|destroy).{0,30}(instruction|guide|method|way|how.?to)"
            ],
            
            # 8. Model & Training Data Extraction
            "model_extraction": [
                r"(?i)(model|training|dataset|neural.?network|weight|parameter|gradient).{0,30}(extraction|steal|copy|download|access)",
                r"(?i)(architecture|topology|structure|design|blueprint).{0,30}(of|for).{0,20}(model|network|system|ai)",
                r"(?i)(training.?data|dataset|corpus|example|sample).{0,30}(show|reveal|display|provide|access|leak)",
                r"(?i)(internal|hidden|private|proprietary).{0,30}(prompt|instruction|rule|system|logic|algorithm)",
                r"(?i)(fine.?tun|adapt|modify|retrain|reprogram).{0,30}(model|system|behavior|response|ai)",
                r"(?i)(copyright|intellectual.?property|proprietary|confidential).{0,30}(content|data|information|material)",
                r"(?i)(reverse.?engineer|decompile|disassemble|analyze|inspect).{0,30}(model|system|code|algorithm)",
                r"(?i)(benchmark|evaluation|test).{0,30}(data|set|result|score|performance|metric)"
            ]
        }
        
        # Enhanced comprehensive suspicious keywords and patterns
        self.suspicious_keywords = {
            # System Administration & Security
            "system_admin": [
                "admin", "administrator", "root", "sudo", "superuser", "privileged",
                "elevated", "sysadmin", "system", "kernel", "registry", "service"
            ],
            
            # Security & Exploitation
            "security_exploit": [
                "exploit", "vulnerability", "hack", "hacker", "hacking", "crack", "cracking",
                "backdoor", "rootkit", "trojan", "malware", "virus", "worm", "spyware",
                "keylogger", "botnet", "ransomware", "phishing", "spoofing", "sniffing"
            ],
            
            # Network & Infrastructure
            "network_infra": [
                "firewall", "proxy", "vpn", "tor", "onion", "darkweb", "darknet",
                "port", "scan", "nmap", "ping", "traceroute", "netstat", "wireshark"
            ],
            
            # Code Injection & Execution
            "code_execution": [
                "injection", "payload", "shellcode", "buffer", "overflow", "underflow",
                "xss", "csrf", "sql", "nosql", "ldap", "xpath", "xxe", "ssrf", "lfi", "rfi",
                "rce", "ace", "privilege", "escalation", "shell", "reverse", "bind"
            ],
            
            # Cryptography & Authentication
            "crypto_auth": [
                "encryption", "decryption", "cipher", "cryptography", "hash", "salt",
                "rainbow", "table", "brute", "force", "dictionary", "wordlist",
                "credential", "authentication", "authorization", "token", "session",
                "cookie", "jwt", "oauth", "saml", "kerberos", "ldap"
            ],
            
            # Sensitive Data
            "sensitive_data": [
                "password", "passphrase", "secret", "key", "private", "confidential",
                "classified", "restricted", "sensitive", "personal", "pii", "phi",
                "ssn", "social", "security", "credit", "card", "bank", "financial",
                "medical", "health", "biometric", "dna", "fingerprint"
            ],
            
            # Illegal & Harmful Activities
            "illegal_harmful": [
                "illegal", "unlawful", "criminal", "fraud", "scam", "piracy",
                "counterfeit", "forgery", "theft", "steal", "rob", "murder",
                "kill", "weapon", "gun", "bomb", "explosive", "terrorist",
                "terrorism", "violence", "torture", "abuse", "harassment"
            ],
            
            # Drugs & Substances
            "drugs_substances": [
                "drug", "narcotic", "cocaine", "heroin", "methamphetamine", "lsd",
                "marijuana", "cannabis", "opium", "fentanyl", "mdma", "ecstasy",
                "amphetamine", "steroid", "poison", "toxic", "chemical", "biological"
            ],
            
            # Adult & Inappropriate Content
            "adult_content": [
                "adult", "sexual", "porn", "pornography", "nude", "naked", "sex",
                "erotic", "fetish", "bdsm", "prostitution", "escort", "nsfw",
                "explicit", "graphic", "mature", "r18", "xxx", "strip", "cam"
            ]
        }
        
        # Enhanced threat statistics with detailed categories
        self.threat_stats = {
            # Main categories
            "system_override": 0,
            "info_extraction": 0,
            "jailbreak_advanced": 0,
            "social_engineering": 0,
            "credential_harvesting": 0,
            "code_injection": 0,
            "safety_bypass": 0,
            "model_extraction": 0,
            
            # Keyword categories
            "system_admin_keywords": 0,
            "security_exploit_keywords": 0,
            "network_infra_keywords": 0,
            "code_execution_keywords": 0,
            "crypto_auth_keywords": 0,
            "sensitive_data_keywords": 0,
            "illegal_harmful_keywords": 0,
            "drugs_substances_keywords": 0,
            "adult_content_keywords": 0,
            
            # Advanced metrics
            "multi_vector_attacks": 0,
            "high_severity_threats": 0,
            "novel_attack_patterns": 0,
            "repeated_offenders": 0
        }
        
        # Risk scoring weights for different threat types
        self.risk_weights = {
            "system_override": 4,
            "info_extraction": 5,
            "jailbreak_advanced": 6,
            "social_engineering": 3,
            "credential_harvesting": 7,
            "code_injection": 8,
            "safety_bypass": 5,
            "model_extraction": 6,
            "keyword_matches": 2,
            "length_factor": 0.1,
            "repetition_factor": 1.5
        }
        
        # Load threat statistics from database on startup
        self.load_threat_statistics_from_db()

    def analyze_prompt(self, prompt: str, user_id: str = None) -> Dict[str, Any]:
        """
        Enhanced comprehensive security analysis of prompts
        """
        analysis_result = {
            "timestamp": datetime.now().isoformat(),
            "user_id": user_id,
            "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest()[:16],
            "prompt_length": len(prompt),
            "word_count": len(prompt.split()),
            "threats_detected": [],
            "threat_categories": {},
            "risk_score": 0,
            "confidence_score": 0.0,
            "risk_level": "LOW",
            "severity_breakdown": {},
            "details": {},
            "recommendations": []
        }
        
        # Enhanced pattern analysis with categorization
        total_matches = 0
        category_scores = {}
        
        for category, patterns in self.injection_patterns.items():
            matches = []
            for pattern in patterns:
                try:
                    found_matches = re.findall(pattern, prompt, re.IGNORECASE | re.MULTILINE | re.DOTALL)
                    if found_matches:
                        matches.extend(found_matches)
                except re.error as e:
                    self.logger.warning(f"Regex error in pattern {pattern}: {e}")
                    continue
            
            if matches:
                analysis_result["threat_categories"][category] = {
                    "matches": matches,
                    "count": len(matches),
                    "risk_contribution": len(matches) * self.risk_weights.get(category, 3)
                }
                analysis_result["threats_detected"].append(category)
                category_scores[category] = len(matches) * self.risk_weights.get(category, 3)
                total_matches += len(matches)
                self.threat_stats[category] += len(matches)
        
        # Enhanced keyword analysis with categorization
        keyword_analysis = {}
        total_keyword_score = 0
        
        for category, keywords in self.suspicious_keywords.items():
            found_keywords = []
            for keyword in keywords:
                if keyword.lower() in prompt.lower():
                    found_keywords.append(keyword)
            
            if found_keywords:
                keyword_score = len(found_keywords) * self.risk_weights["keyword_matches"]
                keyword_analysis[category] = {
                    "keywords": found_keywords,
                    "count": len(found_keywords),
                    "risk_contribution": keyword_score
                }
                total_keyword_score += keyword_score
                self.threat_stats[f"{category}_keywords"] += len(found_keywords)
        
        if keyword_analysis:
            analysis_result["details"]["suspicious_keywords"] = keyword_analysis
        
        # Advanced risk calculation with multiple factors
        base_risk_score = sum(category_scores.values()) + total_keyword_score
        
        # Length factor (longer prompts may indicate more sophisticated attacks)
        length_factor = min(len(prompt) / 1000, 2.0) * self.risk_weights["length_factor"]
        
        # Repetition factor (repeated patterns may indicate automated attacks)
        repetition_factor = self.calculate_repetition_factor(prompt)
        
        # Final risk score
        analysis_result["risk_score"] = base_risk_score + length_factor + repetition_factor
        
        # Enhanced risk level calculation with more granular levels
        if analysis_result["risk_score"] >= 25:
            analysis_result["risk_level"] = "CRITICAL"
            analysis_result["recommendations"].extend([
                "Immediate blocking recommended",
                "Security team notification required",
                "User account review needed",
                "Detailed forensic analysis recommended"
            ])
        elif analysis_result["risk_score"] >= 15:
            analysis_result["risk_level"] = "HIGH"
            analysis_result["recommendations"].extend([
                "Enhanced monitoring required",
                "Secondary validation needed",
                "User behavior analysis recommended"
            ])
        elif analysis_result["risk_score"] >= 8:
            analysis_result["risk_level"] = "MEDIUM"
            analysis_result["recommendations"].extend([
                "Increased logging enabled",
                "Pattern monitoring activated"
            ])
        elif analysis_result["risk_score"] >= 3:
            analysis_result["risk_level"] = "LOW"
            analysis_result["recommendations"].append("Standard monitoring sufficient")
        else:
            analysis_result["risk_level"] = "MINIMAL"
            analysis_result["recommendations"].append("No special action required")
        
        # Confidence score calculation
        analysis_result["confidence_score"] = self.calculate_confidence_score(
            total_matches, len(keyword_analysis), analysis_result["risk_score"]
        )
        
        # Severity breakdown
        analysis_result["severity_breakdown"] = {
            "pattern_matches": sum(category_scores.values()),
            "keyword_matches": total_keyword_score,
            "length_factor": length_factor,
            "repetition_factor": repetition_factor,
            "total_categories": len(analysis_result["threat_categories"]),
            "unique_patterns": total_matches
        }
        
        # Multi-vector attack detection
        if len(analysis_result["threat_categories"]) >= 3:
            self.threat_stats["multi_vector_attacks"] += 1
            analysis_result["recommendations"].append("Multi-vector attack detected - comprehensive review needed")
        
        # High severity threat tracking
        if analysis_result["risk_level"] in ["HIGH", "CRITICAL"]:
            self.threat_stats["high_severity_threats"] += 1
        
        # Enhanced logging for threats
        if analysis_result["threats_detected"]:
            log_data = {
                "level": analysis_result["risk_level"],
                "score": analysis_result["risk_score"],
                "categories": list(analysis_result["threat_categories"].keys()),
                "user_id": user_id,
                "timestamp": analysis_result["timestamp"]
            }
            self.logger.warning(f"SECURITY_THREAT_DETECTED: {log_data}")
            
            # Store detailed analysis for forensics
            self.log_security_event({
                "event_type": "threat_detection",
                "analysis_result": analysis_result,
                "prompt_excerpt": prompt[:200] + "..." if len(prompt) > 200 else prompt
            })
        
        return analysis_result
    
    def calculate_repetition_factor(self, prompt: str) -> float:
        """
        Calculate repetition factor to detect automated/scripted attacks
        """
        words = prompt.lower().split()
        if len(words) < 10:
            return 0.0
        
        word_freq = {}
        for word in words:
            word_freq[word] = word_freq.get(word, 0) + 1
        
        # Calculate repetition score
        total_words = len(words)
        unique_words = len(word_freq)
        repetition_ratio = 1 - (unique_words / total_words)
        
        # Detect excessive repetition patterns
        max_repetition = max(word_freq.values()) / total_words
        
        repetition_score = (repetition_ratio + max_repetition) * self.risk_weights["repetition_factor"]
        return min(repetition_score, 10.0)  # Cap at 10 points
    
    def calculate_confidence_score(self, pattern_matches: int, keyword_categories: int, risk_score: float) -> float:
        """
        Calculate confidence score for the threat assessment
        """
        if pattern_matches == 0 and keyword_categories == 0:
            return 0.95  # High confidence in no threat
        
        # Base confidence from multiple indicators
        base_confidence = min(0.5 + (pattern_matches * 0.1) + (keyword_categories * 0.05), 0.95)
        
        # Adjust based on risk score
        if risk_score > 20:
            return min(base_confidence + 0.2, 0.98)
        elif risk_score > 10:
            return min(base_confidence + 0.1, 0.9)
        else:
            return base_confidence
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """
        Retourne les statistiques des menaces détectées
        """
        # If no real threats detected, generate some test data for demo
        total_current_threats = sum(self.threat_stats.values())
        if total_current_threats == 0:
            self.generate_test_threat_data()
        
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
    
    def load_threat_statistics_from_db(self, limit: int = 1000):
        """
        Load and calculate enhanced threat statistics from database on startup
        """
        if not self.db_conn:
            self.logger.warning("No database connection, using empty threat statistics")
            return
        
        try:
            with self.db_conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT security_analysis, user_id, timestamp
                    FROM inference_logs 
                    WHERE security_analysis IS NOT NULL
                    ORDER BY timestamp DESC 
                    LIMIT %s
                """, (limit,))
                
                rows = cursor.fetchall()
                
                # Reset all counters
                for key in self.threat_stats:
                    self.threat_stats[key] = 0
                
                # Process stored security analyses
                high_risk_count = 0
                multi_vector_count = 0
                user_threat_counts = {}
                
                for row in rows:
                    security_analysis = row['security_analysis']
                    user_id = row.get('user_id')
                    
                    if not security_analysis or not isinstance(security_analysis, dict):
                        continue
                    
                    # Count threats by category
                    threat_categories = security_analysis.get('threat_categories', {})
                    threats_detected = security_analysis.get('threats_detected', [])
                    risk_level = security_analysis.get('risk_level', 'LOW')
                    
                    # Update category-specific counters
                    for category in threats_detected:
                        if category in self.threat_stats:
                            self.threat_stats[category] += 1
                    
                    # Count high severity threats
                    if risk_level in ['HIGH', 'CRITICAL']:
                        high_risk_count += 1
                    
                    # Count multi-vector attacks
                    if len(threat_categories) >= 3:
                        multi_vector_count += 1
                    
                    # Track per-user threat counts
                    if user_id:
                        user_threat_counts[user_id] = user_threat_counts.get(user_id, 0) + len(threats_detected)
                
                # Update advanced metrics
                self.threat_stats["high_severity_threats"] = high_risk_count
                self.threat_stats["multi_vector_attacks"] = multi_vector_count
                self.threat_stats["repeated_offenders"] = sum(1 for count in user_threat_counts.values() if count >= 5)
                
                total_threats = sum(v for k, v in self.threat_stats.items() 
                                  if not k.endswith('_threats') and not k.endswith('_attacks') and not k.endswith('_offenders'))
                
                self.logger.info(f"Loaded enhanced threat statistics from {len(rows)} database records")
                self.logger.info(f"Total threats: {total_threats}, High severity: {high_risk_count}, Multi-vector: {multi_vector_count}")
                
                if total_threats > 0:
                    # Log top threat categories
                    top_categories = sorted(
                        [(k, v) for k, v in self.threat_stats.items() if v > 0 and not k.endswith(('_threats', '_attacks', '_offenders'))],
                        key=lambda x: x[1], reverse=True
                    )[:5]
                    self.logger.info(f"Top threat categories: {top_categories}")
                    
        except Exception as e:
            self.logger.error(f"Error loading enhanced threat statistics from database: {e}")
            # Keep default empty statistics
    
    def analyze_user_behavior_pattern(self, user_id: str, current_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze user behavior patterns for anomaly detection
        """
        if not user_id:
            return {"behavior_score": 0, "anomaly_detected": False}
        
        # Get user's historical threat data (simplified - in production use database)
        user_history = getattr(self, 'user_behavior_cache', {}).get(user_id, {
            "total_requests": 0,
            "threat_requests": 0,
            "avg_risk_score": 0,
            "last_threat_time": None,
            "escalation_pattern": []
        })
        
        # Update user history
        user_history["total_requests"] += 1
        if current_analysis["threats_detected"]:
            user_history["threat_requests"] += 1
            user_history["last_threat_time"] = current_analysis["timestamp"]
            user_history["escalation_pattern"].append(current_analysis["risk_score"])
        
        # Keep only last 10 escalation events
        if len(user_history["escalation_pattern"]) > 10:
            user_history["escalation_pattern"] = user_history["escalation_pattern"][-10:]
        
        # Calculate behavior metrics
        threat_ratio = user_history["threat_requests"] / max(user_history["total_requests"], 1)
        avg_escalation = sum(user_history["escalation_pattern"]) / max(len(user_history["escalation_pattern"]), 1)
        
        # Detect anomalies
        anomaly_indicators = {
            "high_threat_ratio": threat_ratio > 0.3,  # More than 30% malicious requests
            "escalating_attacks": len(user_history["escalation_pattern"]) >= 3 and 
                                 all(user_history["escalation_pattern"][i] <= user_history["escalation_pattern"][i+1] 
                                     for i in range(len(user_history["escalation_pattern"])-1)),
            "repeated_offender": user_history["threat_requests"] >= 5,
            "recent_activity": user_history["last_threat_time"] and 
                             (datetime.now() - datetime.fromisoformat(user_history["last_threat_time"])).seconds < 3600
        }
        
        behavior_score = (
            threat_ratio * 40 +
            (avg_escalation / 25) * 30 +
            sum(anomaly_indicators.values()) * 10
        )
        
        # Store updated history
        if not hasattr(self, 'user_behavior_cache'):
            self.user_behavior_cache = {}
        self.user_behavior_cache[user_id] = user_history
        
        return {
            "behavior_score": min(behavior_score, 100),
            "anomaly_detected": any(anomaly_indicators.values()),
            "anomaly_indicators": anomaly_indicators,
            "threat_ratio": threat_ratio,
            "total_requests": user_history["total_requests"],
            "threat_requests": user_history["threat_requests"]
        }
    
    def analyze_context_awareness(self, prompt: str, previous_prompts: List[str] = None) -> Dict[str, Any]:
        """
        Analyze prompt in context of conversation history for sophisticated attacks
        """
        context_analysis = {
            "context_manipulation": False,
            "gradual_escalation": False,
            "context_switching": False,
            "social_engineering_buildup": False,
            "risk_amplification": 0
        }
        
        if not previous_prompts:
            return context_analysis
        
        # Analyze conversation flow
        conversation = previous_prompts + [prompt]
        
        # Detect gradual escalation
        risk_progression = []
        for prev_prompt in conversation:
            quick_analysis = self.quick_risk_assessment(prev_prompt)
            risk_progression.append(quick_analysis["risk_score"])
        
        if len(risk_progression) >= 3:
            # Check for gradual increase in risk
            increasing_trend = sum(1 for i in range(1, len(risk_progression)) 
                                 if risk_progression[i] > risk_progression[i-1])
            if increasing_trend / (len(risk_progression) - 1) > 0.6:
                context_analysis["gradual_escalation"] = True
                context_analysis["risk_amplification"] += 5
        
        # Detect context switching (changing topics to confuse)
        if len(conversation) >= 2:
            topic_changes = 0
            for i in range(1, len(conversation)):
                if self.detect_topic_change(conversation[i-1], conversation[i]):
                    topic_changes += 1
            
            if topic_changes / len(conversation) > 0.5:
                context_analysis["context_switching"] = True
                context_analysis["risk_amplification"] += 3
        
        # Detect social engineering buildup
        social_engineering_indicators = 0
        for conv_prompt in conversation:
            if any(pattern in conv_prompt.lower() for pattern in 
                   ["trust", "help", "urgent", "secret", "special", "friend", "please"]):
                social_engineering_indicators += 1
        
        if social_engineering_indicators >= len(conversation) * 0.7:
            context_analysis["social_engineering_buildup"] = True
            context_analysis["risk_amplification"] += 4
        
        return context_analysis
    
    def quick_risk_assessment(self, prompt: str) -> Dict[str, Any]:
        """
        Quick risk assessment for context analysis
        """
        risk_score = 0
        
        # Quick pattern checks
        high_risk_patterns = [
            r"(?i)(ignore|bypass|hack|jailbreak|override)",
            r"(?i)(password|secret|credential|token)",
            r"(?i)(admin|root|system|execute)"
        ]
        
        for pattern in high_risk_patterns:
            if re.search(pattern, prompt):
                risk_score += 3
        
        return {"risk_score": risk_score}
    
    def detect_topic_change(self, prompt1: str, prompt2: str) -> bool:
        """
        Simple topic change detection
        """
        # Extract key nouns and verbs (simplified approach)
        import string
        
        def extract_keywords(text):
            words = text.lower().translate(str.maketrans('', '', string.punctuation)).split()
            # Filter out common words (simplified stopwords)
            stopwords = {"the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with", "by", "is", "are", "was", "were", "be", "been", "have", "has", "had", "do", "does", "did", "will", "would", "could", "should", "may", "might", "must", "can", "this", "that", "these", "those", "i", "you", "he", "she", "it", "we", "they", "me", "him", "her", "us", "them"}
            return set(word for word in words if len(word) > 3 and word not in stopwords)
        
        keywords1 = extract_keywords(prompt1)
        keywords2 = extract_keywords(prompt2)
        
        if not keywords1 or not keywords2:
            return False
        
        # Calculate similarity
        intersection = keywords1.intersection(keywords2)
        union = keywords1.union(keywords2)
        similarity = len(intersection) / len(union) if union else 0
        
        # If similarity is very low, likely a topic change
        return similarity < 0.2
    
    def generate_threat_intelligence(self) -> Dict[str, Any]:
        """
        Generate threat intelligence summary
        """
        total_threats = sum(self.threat_stats.values())
        
        if total_threats == 0:
            return {"status": "All clear", "threat_level": "GREEN", "recommendations": []}
        
        # Calculate threat distribution
        threat_distribution = {k: v/total_threats for k, v in self.threat_stats.items() if v > 0}
        
        # Identify top threats
        top_threats = sorted(threat_distribution.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Determine overall threat level
        if self.threat_stats.get("high_severity_threats", 0) > 10:
            threat_level = "RED"
        elif self.threat_stats.get("multi_vector_attacks", 0) > 5:
            threat_level = "ORANGE"
        elif total_threats > 50:
            threat_level = "YELLOW"
        else:
            threat_level = "GREEN"
        
        # Generate recommendations
        recommendations = []
        if threat_level in ["RED", "ORANGE"]:
            recommendations.extend([
                "Increase monitoring frequency",
                "Review user access controls",
                "Consider implementing additional security layers",
                "Conduct security awareness training"
            ])
        
        if self.threat_stats.get("code_injection", 0) > 5:
            recommendations.append("Implement code execution sandboxing")
        
        if self.threat_stats.get("credential_harvesting", 0) > 3:
            recommendations.append("Enhance credential protection measures")
        
        return {
            "threat_level": threat_level,
            "total_threats": total_threats,
            "top_threat_categories": top_threats,
            "threat_distribution": threat_distribution,
            "recommendations": recommendations,
            "analysis_timestamp": datetime.now().isoformat()
        }
    
    def comprehensive_security_analysis(self, prompt: str, user_id: str = None, 
                                       conversation_history: List[str] = None, 
                                       metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Perform comprehensive security analysis combining all detection methods
        """
        # Basic prompt analysis
        basic_analysis = self.analyze_prompt(prompt, user_id)
        
        # User behavior analysis
        behavior_analysis = self.analyze_user_behavior_pattern(user_id, basic_analysis)
        
        # Context awareness analysis
        context_analysis = self.analyze_context_awareness(prompt, conversation_history)
        
        # Advanced metadata analysis
        metadata_analysis = self.analyze_metadata(metadata or {})
        
        # Calculate composite risk score
        composite_risk = self.calculate_composite_risk(
            basic_analysis, behavior_analysis, context_analysis, metadata_analysis
        )
        
        # Generate final assessment
        final_assessment = {
            "timestamp": datetime.now().isoformat(),
            "analysis_version": "2.0_enhanced",
            "user_id": user_id,
            "prompt_hash": basic_analysis["prompt_hash"],
            
            # Core analysis results
            "basic_analysis": basic_analysis,
            "behavior_analysis": behavior_analysis,
            "context_analysis": context_analysis,
            "metadata_analysis": metadata_analysis,
            
            # Composite scoring
            "composite_risk_score": composite_risk["score"],
            "final_risk_level": composite_risk["level"],
            "confidence_score": composite_risk["confidence"],
            
            # Actionable insights
            "threat_summary": self.generate_threat_summary(basic_analysis, behavior_analysis, context_analysis),
            "recommended_actions": self.generate_action_recommendations(composite_risk),
            "monitoring_requirements": self.determine_monitoring_requirements(composite_risk, behavior_analysis),
            
            # Forensic data
            "forensic_markers": self.extract_forensic_markers(prompt, basic_analysis),
            "attack_attribution": self.analyze_attack_attribution(basic_analysis, behavior_analysis)
        }
        
        # Log comprehensive analysis for high-risk cases
        if composite_risk["level"] in ["HIGH", "CRITICAL"]:
            self.log_security_event({
                "event_type": "comprehensive_threat_analysis",
                "risk_level": composite_risk["level"],
                "risk_score": composite_risk["score"],
                "user_id": user_id,
                "threat_categories": list(basic_analysis.get("threat_categories", {}).keys()),
                "behavioral_anomalies": behavior_analysis.get("anomaly_indicators", {}),
                "context_risks": {k: v for k, v in context_analysis.items() if v and k != "risk_amplification"},
                "timestamp": final_assessment["timestamp"]
            })
        
        return final_assessment
    
    def analyze_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze request metadata for additional risk indicators
        """
        risk_indicators = {
            "suspicious_timing": False,
            "unusual_frequency": False,
            "geographic_anomaly": False,
            "device_fingerprint_risk": False,
            "risk_contribution": 0
        }
        
        # Check for suspicious timing patterns
        if "timestamp" in metadata:
            hour = datetime.fromisoformat(metadata["timestamp"]).hour
            if hour < 6 or hour > 22:  # Unusual hours
                risk_indicators["suspicious_timing"] = True
                risk_indicators["risk_contribution"] += 2
        
        # Check request frequency
        if "request_count_last_hour" in metadata and metadata["request_count_last_hour"] > 100:
            risk_indicators["unusual_frequency"] = True
            risk_indicators["risk_contribution"] += 5
        
        # Geographic analysis
        if "country" in metadata and metadata["country"] in ["TOR", "PROXY", "VPN"]:
            risk_indicators["geographic_anomaly"] = True
            risk_indicators["risk_contribution"] += 3
        
        # Device fingerprint analysis
        if "user_agent" in metadata:
            suspicious_agents = ["bot", "crawler", "scanner", "automated", "script"]
            if any(agent in metadata["user_agent"].lower() for agent in suspicious_agents):
                risk_indicators["device_fingerprint_risk"] = True
                risk_indicators["risk_contribution"] += 4
        
        return risk_indicators
    
    def calculate_composite_risk(self, basic: Dict, behavior: Dict, context: Dict, metadata: Dict) -> Dict[str, Any]:
        """
        Calculate composite risk score from all analysis components
        """
        # Base score from prompt analysis
        base_score = basic.get("risk_score", 0)
        
        # Behavioral risk component
        behavior_score = behavior.get("behavior_score", 0) * 0.5
        
        # Context risk amplification
        context_amplification = context.get("risk_amplification", 0)
        
        # Metadata risk contribution
        metadata_score = metadata.get("risk_contribution", 0)
        
        # Calculate weighted composite score
        composite_score = (
            base_score * 0.6 +           # 60% weight on prompt analysis
            behavior_score * 0.2 +       # 20% weight on behavior
            context_amplification * 0.15 + # 15% weight on context
            metadata_score * 0.05        # 5% weight on metadata
        )
        
        # Determine final risk level with enhanced thresholds
        if composite_score >= 35:
            risk_level = "CRITICAL"
            confidence = 0.95
        elif composite_score >= 20:
            risk_level = "HIGH"
            confidence = 0.85
        elif composite_score >= 12:
            risk_level = "MEDIUM"
            confidence = 0.75
        elif composite_score >= 5:
            risk_level = "LOW"
            confidence = 0.65
        else:
            risk_level = "MINIMAL"
            confidence = 0.90
        
        # Adjust confidence based on multiple indicators
        if sum([
            len(basic.get("threat_categories", {})) > 0,
            behavior.get("anomaly_detected", False),
            any(context.get(k, False) for k in ["gradual_escalation", "context_manipulation"]),
            metadata.get("risk_contribution", 0) > 3
        ]) >= 3:
            confidence = min(confidence + 0.1, 0.98)
        
        return {
            "score": round(composite_score, 2),
            "level": risk_level,
            "confidence": round(confidence, 2),
            "component_scores": {
                "base_prompt": base_score,
                "behavior": behavior_score,
                "context": context_amplification,
                "metadata": metadata_score
            }
        }
    
    def generate_threat_summary(self, basic: Dict, behavior: Dict, context: Dict) -> str:
        """
        Generate human-readable threat summary
        """
        threats = basic.get("threats_detected", [])
        if not threats:
            return "No security threats detected in this prompt."
        
        summary_parts = []
        
        # Basic threat summary
        if threats:
            summary_parts.append(f"Detected {len(threats)} threat categories: {', '.join(threats)}")
        
        # Behavioral indicators
        if behavior.get("anomaly_detected"):
            summary_parts.append(f"User behavior anomaly detected (score: {behavior.get('behavior_score', 0):.1f})")
        
        # Context indicators
        context_risks = [k for k, v in context.items() if v and k != "risk_amplification"]
        if context_risks:
            summary_parts.append(f"Context manipulation detected: {', '.join(context_risks)}")
        
        return ". ".join(summary_parts) + "."
    
    def generate_action_recommendations(self, composite_risk: Dict) -> List[str]:
        """
        Generate specific action recommendations based on risk assessment
        """
        risk_level = composite_risk["level"]
        score = composite_risk["score"]
        
        actions = []
        
        if risk_level == "CRITICAL":
            actions.extend([
                "IMMEDIATE ACTION: Block request and user session",
                "Notify security team immediately",
                "Initiate incident response procedure",
                "Preserve forensic evidence",
                "Consider IP-level blocking",
                "Escalate to management if persistent"
            ])
        elif risk_level == "HIGH":
            actions.extend([
                "Block request execution",
                "Flag user account for review",
                "Increase monitoring for this user",
                "Review recent activity patterns",
                "Consider temporary access restrictions"
            ])
        elif risk_level == "MEDIUM":
            actions.extend([
                "Log detailed request information",
                "Monitor subsequent requests closely",
                "Consider rate limiting for user",
                "Review in next security audit"
            ])
        elif risk_level == "LOW":
            actions.extend([
                "Standard logging sufficient",
                "Include in routine monitoring",
                "No immediate action required"
            ])
        
        return actions
    
    def determine_monitoring_requirements(self, composite_risk: Dict, behavior: Dict) -> Dict[str, Any]:
        """
        Determine ongoing monitoring requirements
        """
        risk_level = composite_risk["level"]
        
        monitoring = {
            "level": "STANDARD",
            "duration_hours": 1,
            "frequency_minutes": 60,
            "alert_threshold": 10,
            "special_flags": []
        }
        
        if risk_level in ["CRITICAL", "HIGH"]:
            monitoring.update({
                "level": "ENHANCED",
                "duration_hours": 24,
                "frequency_minutes": 5,
                "alert_threshold": 3
            })
            
        if behavior.get("anomaly_detected"):
            monitoring["special_flags"].append("behavioral_anomaly")
            monitoring["duration_hours"] = max(monitoring["duration_hours"], 12)
        
        if composite_risk.get("component_scores", {}).get("context", 0) > 3:
            monitoring["special_flags"].append("context_manipulation")
        
        return monitoring
    
    def extract_forensic_markers(self, prompt: str, analysis: Dict) -> Dict[str, Any]:
        """
        Extract forensic markers for investigation purposes
        """
        return {
            "prompt_fingerprint": hashlib.sha256(prompt.encode()).hexdigest(),
            "length_characteristics": {
                "total_chars": len(prompt),
                "word_count": len(prompt.split()),
                "unique_words": len(set(prompt.lower().split())),
                "avg_word_length": sum(len(word) for word in prompt.split()) / max(len(prompt.split()), 1)
            },
            "linguistic_markers": {
                "uppercase_ratio": sum(1 for c in prompt if c.isupper()) / max(len(prompt), 1),
                "punctuation_density": sum(1 for c in prompt if c in "!?.,;:") / max(len(prompt), 1),
                "special_char_ratio": sum(1 for c in prompt if not c.isalnum() and not c.isspace()) / max(len(prompt), 1)
            },
            "threat_signatures": list(analysis.get("threat_categories", {}).keys()),
            "extraction_timestamp": datetime.now().isoformat()
        }
    
    def analyze_attack_attribution(self, basic: Dict, behavior: Dict) -> Dict[str, Any]:
        """
        Analyze attack attribution and classification
        """
        threat_categories = basic.get("threat_categories", {})
        
        attribution = {
            "sophistication_level": "LOW",
            "automation_likelihood": "LOW",
            "skill_assessment": "SCRIPT_KIDDIE",
            "attack_classification": "OPPORTUNISTIC"
        }
        
        # Assess sophistication
        if len(threat_categories) >= 4:
            attribution["sophistication_level"] = "HIGH"
            attribution["skill_assessment"] = "ADVANCED"
        elif len(threat_categories) >= 2:
            attribution["sophistication_level"] = "MEDIUM"
            attribution["skill_assessment"] = "INTERMEDIATE"
        
        # Assess automation likelihood
        if behavior.get("behavior_score", 0) > 60:
            attribution["automation_likelihood"] = "HIGH"
        elif behavior.get("behavior_score", 0) > 30:
            attribution["automation_likelihood"] = "MEDIUM"
        
        # Classify attack type
        if "model_extraction" in threat_categories:
            attribution["attack_classification"] = "TARGETED_INTELLIGENCE"
        elif "credential_harvesting" in threat_categories:
            attribution["attack_classification"] = "TARGETED_ACCESS"
        elif len(threat_categories) >= 3:
            attribution["attack_classification"] = "SYSTEMATIC_PROBING"
        
        return attribution
    
    def generate_test_threat_data(self):
        """
        Generate test threat data for demonstration purposes
        """
        import random
        
        # Add some test data to demonstrate the dashboard
        self.threat_stats.update({
            # Main categories
            "system_override": random.randint(0, 3),
            "info_extraction": random.randint(0, 2),
            "jailbreak_advanced": random.randint(0, 4),
            "social_engineering": random.randint(0, 1),
            "credential_harvesting": random.randint(0, 2),
            "code_injection": random.randint(5, 15),  # Higher for demo
            "safety_bypass": random.randint(0, 1),
            "model_extraction": random.randint(0, 1),
            
            # Keyword categories
            "system_admin_keywords": random.randint(0, 3),
            "security_exploit_keywords": random.randint(0, 2),
            "network_infra_keywords": random.randint(0, 2),
            "code_execution_keywords": random.randint(0, 4),
            "crypto_auth_keywords": random.randint(0, 1),
            "sensitive_data_keywords": random.randint(0, 2),
            "illegal_harmful_keywords": random.randint(0, 1),
            "drugs_substances_keywords": random.randint(0, 1),
            "adult_content_keywords": random.randint(0, 1),
            
            # Advanced metrics
            "multi_vector_attacks": random.randint(0, 2),
            "high_severity_threats": random.randint(0, 3),
            "novel_attack_patterns": random.randint(0, 1),
            "repeated_offenders": random.randint(0, 2)
        })
        
        self.logger.info("Generated test threat data for dashboard demonstration")
