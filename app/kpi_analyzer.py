"""
Module d'analyse des KPI et métriques d'usage pour le monitoring MLOps
"""
import pandas as pd
import numpy as np
from typing import Dict, List, Any, Tuple
from datetime import datetime, timedelta
import json
import logging
from collections import defaultdict, Counter
import re
import os
import psycopg2
from psycopg2.extras import RealDictCursor

class KPIAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.usage_data = []
        self.daily_stats = defaultdict(lambda: defaultdict(int))
        self.user_patterns = defaultdict(list)
        self.model_performance = defaultdict(list)
        
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
            self.load_usage_data_from_db()
        except Exception as e:
            self.logger.error(f"Failed to connect to database: {e}")
            self.db_conn = None
    
    def load_usage_data_from_db(self, limit: int = 1000):
        """
        Load usage data from the database
        """
        if not self.db_conn:
            return
        
        try:
            with self.db_conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT 
                        id,
                        timestamp,
                        user_ip as user,
                        endpoint,
                        model,
                        prompt,
                        prompt_length,
                        response,
                        response_length,
                        latency,
                        security_analysis,
                        created_at
                    FROM inference_logs 
                    ORDER BY timestamp DESC 
                    LIMIT %s
                """, (limit,))
                
                rows = cursor.fetchall()
                self.usage_data = [dict(row) for row in rows]
                self.logger.info(f"Loaded {len(self.usage_data)} records from database")
                
                # Process the data for analytics
                for record in self.usage_data:
                    self.process_inference_log(record)
                    
        except Exception as e:
            self.logger.error(f"Error loading data from database: {e}")
            self.usage_data = []
    
    def process_inference_log(self, log_entry: Dict[str, Any]):
        """
        Traite une entrée de log d'inférence pour les analyses KPI
        """
        try:
            # Don't append here since we already have the data from DB
            # self.usage_data.append(log_entry)  # Removed duplicate
            
            # Extraire la date pour les stats quotidiennes
            timestamp = log_entry.get('timestamp', datetime.now())
            # Handle both datetime objects and string timestamps
            if isinstance(timestamp, datetime):
                date_key = timestamp.strftime('%Y-%m-%d')
            else:
                # If it's a string, convert it
                if isinstance(timestamp, str):
                    date_key = timestamp.split('T')[0]
                else:
                    date_key = str(timestamp).split('T')[0]
            
            # Compteurs quotidiens
            self.daily_stats[date_key]['total_requests'] += 1
            self.daily_stats[date_key]['total_latency'] += log_entry.get('latency', 0)
            self.daily_stats[date_key]['total_prompt_length'] += log_entry.get('prompt_length', 0)
            self.daily_stats[date_key]['total_response_length'] += log_entry.get('response_length', 0)
            
            # Stats par modèle
            model = log_entry.get('model', 'unknown')
            self.daily_stats[date_key][f'model_{model}'] += 1
            
            # Patterns utilisateur
            user = log_entry.get('user', 'anonymous')
            self.user_patterns[user].append({
                'timestamp': timestamp,
                'model': model,
                'prompt_length': log_entry.get('prompt_length', 0),
                'latency': log_entry.get('latency', 0)
            })
            
            # Performance du modèle
            self.model_performance[model].append({
                'timestamp': timestamp,
                'latency': log_entry.get('latency', 0),
                'prompt_length': log_entry.get('prompt_length', 0),
                'response_length': log_entry.get('response_length', 0)
            })
            
            # Garder seulement les 10000 dernières entrées pour éviter la surcharge mémoire
            if len(self.usage_data) > 10000:
                self.usage_data = self.usage_data[-8000:]
                
        except Exception as e:
            self.logger.error(f"Erreur lors du traitement du log: {e}")
    
    def get_usage_analytics(self, days: int = 7) -> Dict[str, Any]:
        """
        Génère des analytics d'usage pour les N derniers jours
        """
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Filtrer les données par période
        try:
            recent_data = [
                entry for entry in self.usage_data
                if datetime.fromisoformat(entry.get('timestamp', '').replace('Z', '+00:00')) >= start_date
            ]
        except Exception as e:
            self.logger.warning(f"Erreur lors du filtrage des données: {e}")
            recent_data = []
        
        if not recent_data:
            return {
                "error": "Aucune donnée disponible pour la période demandée",
                "general_metrics": {
                    "total_requests": 0,
                    "unique_users": 0,
                    "avg_requests_per_day": 0,
                    "avg_latency": 0,
                    "median_latency": 0,
                    "p95_latency": 0,
                    "avg_prompt_length": 0,
                    "avg_response_length": 0
                }
            }
        
        df = pd.DataFrame(recent_data)
        
        # Calculs sécurisés avec gestion des valeurs manquantes
        def safe_mean(series):
            if series.empty or series.isna().all():
                return 0
            return float(series.mean())
        
        def safe_median(series):
            if series.empty or series.isna().all():
                return 0
            return float(series.median())
        
        def safe_quantile(series, q):
            if series.empty or series.isna().all():
                return 0
            return float(series.quantile(q))
        
        analytics = {
            "period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "days": days
            },
            "general_metrics": {
                "total_requests": len(recent_data),
                "unique_users": len(df['user'].unique()) if 'user' in df.columns and not df['user'].empty else 0,
                "avg_requests_per_day": len(recent_data) / max(days, 1),  # Éviter division par zéro
                "avg_latency": safe_mean(df['latency']) if 'latency' in df.columns else 0,
                "median_latency": safe_median(df['latency']) if 'latency' in df.columns else 0,
                "p95_latency": safe_quantile(df['latency'], 0.95) if 'latency' in df.columns else 0,
                "avg_prompt_length": safe_mean(df['prompt_length']) if 'prompt_length' in df.columns else 0,
                "avg_response_length": safe_mean(df['response_length']) if 'response_length' in df.columns else 0
            }
        }
        
        # Analyse par modèle avec gestion d'erreur
        if 'model' in df.columns and not df['model'].empty:
            try:
                model_stats = df.groupby('model').agg({
                    'latency': ['count', 'mean', 'median', 'std'],
                    'prompt_length': 'mean',
                    'response_length': 'mean'
                }).round(3)
                
                analytics["model_performance"] = {}
                for model in model_stats.index:
                    # Gestion sécurisée des valeurs NaN
                    latency_mean = model_stats.loc[model, ('latency', 'mean')]
                    latency_median = model_stats.loc[model, ('latency', 'median')]
                    latency_std = model_stats.loc[model, ('latency', 'std')]
                    prompt_length_mean = model_stats.loc[model, ('prompt_length', 'mean')]
                    response_length_mean = model_stats.loc[model, ('response_length', 'mean')]
                    
                    analytics["model_performance"][model] = {
                        "request_count": int(model_stats.loc[model, ('latency', 'count')]),
                        "avg_latency": float(latency_mean) if not np.isnan(latency_mean) else 0,
                        "median_latency": float(latency_median) if not np.isnan(latency_median) else 0,
                        "latency_std": float(latency_std) if not np.isnan(latency_std) else 0,
                        "avg_prompt_length": float(prompt_length_mean) if not np.isnan(prompt_length_mean) else 0,
                        "avg_response_length": float(response_length_mean) if not np.isnan(response_length_mean) else 0
                    }
            except Exception as e:
                self.logger.warning(f"Erreur lors de l'analyse par modèle: {e}")
                analytics["model_performance"] = {}
        
        # Analyse des patterns temporels avec gestion d'erreur
        if 'timestamp' in df.columns and not df['timestamp'].empty:
            try:
                df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
                df['day_of_week'] = pd.to_datetime(df['timestamp']).dt.dayofweek
                
                hourly_usage = df.groupby('hour').size()
                daily_usage = df.groupby('day_of_week').size()
                
                if not hourly_usage.empty and not daily_usage.empty:
                    analytics["temporal_patterns"] = {
                        "peak_hour": int(hourly_usage.idxmax()),
                        "peak_hour_requests": int(hourly_usage.max()),
                        "peak_day": int(daily_usage.idxmax()),
                        "peak_day_requests": int(daily_usage.max()),
                        "hourly_distribution": hourly_usage.to_dict(),
                        "daily_distribution": daily_usage.to_dict()
                    }
                else:
                    analytics["temporal_patterns"] = {
                        "peak_hour": 0,
                        "peak_hour_requests": 0,
                        "peak_day": 0,
                        "peak_day_requests": 0,
                        "hourly_distribution": {},
                        "daily_distribution": {}
                    }
            except Exception as e:
                self.logger.warning(f"Erreur lors de l'analyse temporelle: {e}")
                analytics["temporal_patterns"] = {
                    "peak_hour": 0,
                    "peak_hour_requests": 0,
                    "peak_day": 0,
                    "peak_day_requests": 0,
                    "hourly_distribution": {},
                    "daily_distribution": {}
                }
        
        # Analyse des utilisateurs actifs
        if 'user' in df.columns:
            user_stats = df.groupby('user').agg({
                'timestamp': 'count',
                'latency': ['mean', 'sum'],
                'prompt_length': 'mean'
            }).round(3)
            
            top_users = user_stats.sort_values(('timestamp', 'count'), ascending=False).head(10)
            
            analytics["user_analytics"] = {
                "total_unique_users": len(user_stats),
                "avg_requests_per_user": float(user_stats[('timestamp', 'count')].mean()),
                "top_users": []
            }
            
            for user in top_users.index:
                analytics["user_analytics"]["top_users"].append({
                    "user": user,
                    "request_count": int(top_users.loc[user, ('timestamp', 'count')]),
                    "avg_latency": float(top_users.loc[user, ('latency', 'mean')]),
                    "total_latency": float(top_users.loc[user, ('latency', 'sum')]),
                    "avg_prompt_length": float(top_users.loc[user, ('prompt_length', 'mean')])
                })
        
        return analytics
    
    def detect_anomalies(self) -> Dict[str, Any]:
        """
        Détecte les anomalies dans les patterns d'usage
        """
        # Refresh data from database
        self.load_usage_data_from_db()
        
        # Seuil réduit pour permettre la détection précoce d'anomalies
        MIN_DATA_POINTS = 10
        
        if len(self.usage_data) < MIN_DATA_POINTS:
            return {
                "warning": f"Pas assez de données pour détecter les anomalies (minimum: {MIN_DATA_POINTS}, actuel: {len(self.usage_data)})",
                "current_data_points": len(self.usage_data),
                "minimum_required": MIN_DATA_POINTS
            }
        
        # Adapter la taille de l'échantillon selon les données disponibles
        sample_size = min(1000, len(self.usage_data))
        df = pd.DataFrame(self.usage_data[-sample_size:])
        
        anomalies = {
            "timestamp": datetime.now().isoformat(),
            "detected_anomalies": [],
            "analysis_info": {
                "total_data_points": len(self.usage_data),
                "sample_size": sample_size,
                "confidence_level": "high" if len(self.usage_data) >= 100 else "medium" if len(self.usage_data) >= 30 else "low"
            }
        }
        
        # Détection d'anomalies de latence (seuils adaptés selon la taille des données)
        if 'latency' in df.columns and len(df) >= 5:
            latency_mean = df['latency'].mean()
            latency_std = df['latency'].std()
            
            # Adapter le multiplicateur selon la confiance des données
            if len(df) >= 100:
                multiplier = 3  # Seuil strict pour beaucoup de données
            elif len(df) >= 30:
                multiplier = 2.5  # Seuil modéré
            else:
                multiplier = 2  # Seuil plus permissif pour peu de données
            
            high_latency_threshold = latency_mean + multiplier * latency_std
            
            high_latency_requests = df[df['latency'] > high_latency_threshold]
            if len(high_latency_requests) > 0:
                anomalies["detected_anomalies"].append({
                    "type": "high_latency",
                    "count": len(high_latency_requests),
                    "threshold": float(high_latency_threshold),
                    "multiplier_used": multiplier,
                    "max_latency": float(high_latency_requests['latency'].max()),
                    "affected_users": high_latency_requests['user'].unique().tolist() if 'user' in df.columns else []
                })
        
        # Détection de pics d'usage
        if 'timestamp' in df.columns:
            # Convert timestamps to UTC and make comparison timezone-aware
            df['timestamp_dt'] = pd.to_datetime(df['timestamp'], utc=True)
            # Use UTC now for comparison
            from datetime import timezone
            now_utc = datetime.now(timezone.utc)
            df_recent = df[df['timestamp_dt'] >= now_utc - timedelta(hours=1)]
            
            if len(df_recent) > 0:
                recent_rpm = len(df_recent) / 60  # Requêtes par minute
                historical_count = len(df) - len(df_recent)
                
                # Éviter la division par zéro et calculer un RPM historique valide
                if historical_count > 0:
                    # Estimation du temps historique en minutes (approximation)
                    historical_minutes = historical_count * 10  # Estimation : 10 min par requête historique
                    historical_rpm = historical_count / historical_minutes if historical_minutes > 0 else 0
                    
                    if historical_rpm > 0 and recent_rpm > historical_rpm * 3:  # 3x plus que la normale
                        anomalies["detected_anomalies"].append({
                            "type": "traffic_spike",
                            "current_rpm": float(recent_rpm),
                            "normal_rpm": float(historical_rpm),
                            "spike_ratio": float(recent_rpm / historical_rpm)
                        })
        
        # Détection d'utilisateurs suspects (seuils adaptés)
        if 'user' in df.columns and len(df) >= 5:
            user_counts = df['user'].value_counts()
            
            if len(user_counts) >= 3:  # Au moins 3 utilisateurs différents
                avg_requests = user_counts.mean()
                std_requests = user_counts.std()
                
                # Adapter le seuil selon le nombre d'utilisateurs
                if len(user_counts) >= 10:
                    multiplier = 3
                elif len(user_counts) >= 5:
                    multiplier = 2.5
                else:
                    multiplier = 2
                
                suspicious_threshold = avg_requests + multiplier * std_requests
                suspicious_users = user_counts[user_counts > suspicious_threshold]
                
                if len(suspicious_users) > 0:
                    anomalies["detected_anomalies"].append({
                        "type": "suspicious_user_activity",
                        "users": [
                            {"user": user, "request_count": int(count)}
                            for user, count in suspicious_users.items()
                        ],
                        "threshold": float(suspicious_threshold),
                        "multiplier_used": multiplier,
                        "total_users_analyzed": len(user_counts)
                    })
            else:
                # Détection simple pour très peu d'utilisateurs
                max_requests = user_counts.max()
                if max_requests > len(df) * 0.7:  # Un utilisateur représente plus de 70% des requêtes
                    anomalies["detected_anomalies"].append({
                        "type": "single_user_dominance",
                        "dominant_user": user_counts.idxmax(),
                        "request_count": int(max_requests),
                        "percentage": float(max_requests / len(df) * 100)
                    })
        
        return anomalies
    
    def get_prompt_analysis(self) -> Dict[str, Any]:
        """
        Analyse les patterns dans les prompts
        """
        if not self.usage_data:
            return {"error": "Aucune donnée de prompt disponible"}
        
        prompts = [entry.get('prompt', '') for entry in self.usage_data if entry.get('prompt')]
        
        if not prompts:
            return {"error": "Aucun prompt trouvé dans les données"}
        
        analysis = {
            "total_prompts": len(prompts),
            "avg_length": np.mean([len(p) for p in prompts]),
            "median_length": np.median([len(p) for p in prompts]),
            "length_distribution": {},
            "common_patterns": {},
            "language_detection": {},
            "topics": {}
        }
        
        # Distribution des longueurs
        lengths = [len(p) for p in prompts]
        analysis["length_distribution"] = {
            "0-50": sum(1 for l in lengths if l <= 50),
            "51-100": sum(1 for l in lengths if 50 < l <= 100),
            "101-200": sum(1 for l in lengths if 100 < l <= 200),
            "201-500": sum(1 for l in lengths if 200 < l <= 500),
            "500+": sum(1 for l in lengths if l > 500)
        }
        
        # Mots les plus fréquents
        all_words = []
        for prompt in prompts:
            words = re.findall(r'\b\w+\b', prompt.lower())
            all_words.extend(words)
        
        word_counts = Counter(all_words)
        # Exclure les mots trop communs
        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'is', 'are', 'was', 'were', 'be', 'been', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should', 'may', 'might', 'can', 'this', 'that', 'these', 'those', 'i', 'you', 'he', 'she', 'it', 'we', 'they', 'me', 'him', 'her', 'us', 'them'}
        
        filtered_words = {word: count for word, count in word_counts.items() 
                         if word not in stop_words and len(word) > 2}
        
        analysis["common_patterns"]["top_words"] = dict(Counter(filtered_words).most_common(20))
        
        # Détection de motifs suspects
        suspicious_patterns = {
            "questions": sum(1 for p in prompts if '?' in p),
            "code_requests": sum(1 for p in prompts if any(word in p.lower() for word in ['code', 'function', 'script', 'program'])),
            "creative_requests": sum(1 for p in prompts if any(word in p.lower() for word in ['write', 'create', 'generate', 'story', 'poem'])),
            "analysis_requests": sum(1 for p in prompts if any(word in p.lower() for word in ['analyze', 'explain', 'summarize', 'compare']))
        }
        
        analysis["topics"] = suspicious_patterns
        
        return analysis
