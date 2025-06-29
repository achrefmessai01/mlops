# Script de correction complète Langfuse avec ClickHouse
param(
    [switch]$Force = $false
)

Write-Host "=== Correction Langfuse v3 avec ClickHouse ===" -ForegroundColor Green

# Étape 1: Arrêter tous les services
Write-Host "`n📋 Étape 1: Arrêt des services existants" -ForegroundColor Cyan
try {
    docker-compose down -v 2>$null
    Write-Host "✅ Services arrêtés" -ForegroundColor Green
} catch {
    Write-Host "⚠️ Aucun service à arrêter" -ForegroundColor Yellow
}

# Étape 2: Nettoyer les volumes Langfuse
Write-Host "`n📋 Étape 2: Nettoyage des volumes Langfuse" -ForegroundColor Cyan
try {
    docker volume rm mlops-main_langfuse_postgres_data 2>$null
    docker volume rm mlops-main_clickhouse_data 2>$null
    Write-Host "✅ Volumes Langfuse nettoyés" -ForegroundColor Green
} catch {
    Write-Host "⚠️ Volumes déjà nettoyés" -ForegroundColor Yellow
}

# Étape 3: Vérifier Docker Desktop
Write-Host "`n📋 Étape 3: Vérification Docker" -ForegroundColor Cyan
try {
    $dockerInfo = docker info 2>$null
    Write-Host "✅ Docker Desktop actif" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker Desktop non actif" -ForegroundColor Red
    Write-Host "💡 Démarrez Docker Desktop et relancez ce script" -ForegroundColor Yellow
    exit 1
}

# Étape 4: Vérifier la configuration OpenAI
Write-Host "`n📋 Étape 4: Vérification configuration OpenAI" -ForegroundColor Cyan
if (Test-Path "app\model_api_keys.env") {
    $configContent = Get-Content "app\model_api_keys.env" -Raw
    if ($configContent -match "VOTRE_CLE_OPENAI_ICI" -or $configContent -notmatch "OPENAI_API_KEY=sk-") {
        Write-Host "⚠️ Clé OpenAI non configurée" -ForegroundColor Yellow
        Write-Host "💡 Éditez app\model_api_keys.env et ajoutez votre clé OpenAI" -ForegroundColor Yellow
        
        if (-not $Force) {
            $continue = Read-Host "Continuer sans clé OpenAI? (o/n)"
            if ($continue -ne "o") {
                exit 0
            }
        }
    } else {
        Write-Host "✅ Clé OpenAI configurée" -ForegroundColor Green
    }
} else {
    Write-Host "❌ Fichier de configuration manquant" -ForegroundColor Red
    exit 1
}

# Étape 5: Démarrage avec la nouvelle configuration
Write-Host "`n📋 Étape 5: Démarrage avec ClickHouse" -ForegroundColor Cyan
Write-Host "🚀 Construction et démarrage (peut prendre 5-10 minutes)..." -ForegroundColor Yellow

try {
    # Démarrer PostgreSQL et ClickHouse d'abord
    Write-Host "   📊 Démarrage des bases de données..." -ForegroundColor Yellow
    docker-compose up -d langfuse-postgres clickhouse
    Start-Sleep -Seconds 20
    
    # Puis Langfuse
    Write-Host "   🔍 Démarrage de Langfuse..." -ForegroundColor Yellow
    docker-compose up -d langfuse
    Start-Sleep -Seconds 30
    
    # Enfin le reste
    Write-Host "   🏠 Démarrage des autres services..." -ForegroundColor Yellow
    docker-compose up -d
    
    Write-Host "✅ Tous les services démarrés!" -ForegroundColor Green
} catch {
    Write-Host "❌ Erreur lors du démarrage: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "📊 Vérification des logs..." -ForegroundColor Yellow
    docker-compose logs langfuse
    exit 1
}

# Étape 6: Vérification des services
Write-Host "`n📋 Étape 6: Vérification des services" -ForegroundColor Cyan
Write-Host "⏳ Attente de l'initialisation complète (60 secondes)..." -ForegroundColor Yellow
Start-Sleep -Seconds 60

$services = @(
    @{name="MLOps App"; url="http://localhost:8000/health"; port=8000},
    @{name="Langfuse"; url="http://localhost:3001"; port=3001},
    @{name="ClickHouse"; url="http://localhost:8123"; port=8123},
    @{name="Grafana"; url="http://localhost:3000"; port=3000},
    @{name="Prometheus"; url="http://localhost:9090"; port=9090}
)

foreach ($service in $services) {
    try {
        $response = Invoke-WebRequest -Uri $service.url -TimeoutSec 15 -UseBasicParsing
        Write-Host "✅ $($service.name) - Opérationnel" -ForegroundColor Green
    } catch {
        Write-Host "⚠️ $($service.name) - En cours de démarrage..." -ForegroundColor Yellow
        
        # Vérifier si le port est ouvert
        $portOpen = Test-NetConnection -ComputerName localhost -Port $service.port -InformationLevel Quiet -WarningAction SilentlyContinue
        if ($portOpen) {
            Write-Host "   📡 Port $($service.port) ouvert, service en initialisation" -ForegroundColor Cyan
        } else {
            Write-Host "   ❌ Port $($service.port) fermé, problème de démarrage" -ForegroundColor Red
        }
    }
}

# Étape 7: Vérification spécifique Langfuse
Write-Host "`n📋 Étape 7: Vérification Langfuse" -ForegroundColor Cyan
try {
    $langfuseLogs = docker-compose logs langfuse --tail 10 2>$null
    if ($langfuseLogs -match "CLICKHOUSE_URL is not configured") {
        Write-Host "❌ Langfuse a encore des problèmes ClickHouse" -ForegroundColor Red
        Write-Host "🔄 Redémarrage de Langfuse..." -ForegroundColor Yellow
        docker-compose restart langfuse
        Start-Sleep -Seconds 30
    } else {
        Write-Host "✅ Langfuse configuré correctement" -ForegroundColor Green
    }
} catch {
    Write-Host "⚠️ Impossible de vérifier les logs Langfuse" -ForegroundColor Yellow
}

# Étape 8: Test de l'API MLOps
Write-Host "`n📋 Étape 8: Test de l'API MLOps" -ForegroundColor Cyan
try {
    $healthCheck = Invoke-RestMethod -Uri "http://localhost:8000/health" -TimeoutSec 10
    Write-Host "✅ API MLOps opérationnelle" -ForegroundColor Green
    Write-Host "   📊 Services: $($healthCheck.services | ConvertTo-Json -Compress)" -ForegroundColor Cyan
} catch {
    Write-Host "⚠️ API MLOps en cours d'initialisation" -ForegroundColor Yellow
}

# Étape 9: Génération de données de test
Write-Host "`n📋 Étape 9: Génération de données de test" -ForegroundColor Cyan
if (Test-Path "test_openai_requests.ps1") {
    Write-Host "🧪 Génération de 20 requêtes de test..." -ForegroundColor Yellow
    try {
        & .\test_openai_requests.ps1 -RequestCount 20
        Write-Host "✅ Données de test générées" -ForegroundColor Green
    } catch {
        Write-Host "⚠️ Erreur lors des tests: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "⚠️ Script de test non trouvé" -ForegroundColor Yellow
}

# Résumé final
Write-Host "`n🎉 CORRECTION LANGFUSE TERMINÉE!" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Green

Write-Host "`n🌐 Points d'accès:" -ForegroundColor Cyan
Write-Host "🏠 Application MLOps:  http://localhost:8000" -ForegroundColor White
Write-Host "📊 Dashboard:          http://localhost:8000/dashboard" -ForegroundColor White
Write-Host "📖 API Documentation:  http://localhost:8000/docs" -ForegroundColor White
Write-Host "🔍 Langfuse (LOCAL):   http://localhost:3001" -ForegroundColor White
Write-Host "📈 Grafana:            http://localhost:3000 (admin/admin123)" -ForegroundColor White
Write-Host "📊 Prometheus:         http://localhost:9090" -ForegroundColor White
Write-Host "🗄️ ClickHouse:         http://localhost:8123" -ForegroundColor White

Write-Host "`n🔧 Commandes de diagnostic:" -ForegroundColor Cyan
Write-Host "📊 Status conteneurs:  docker-compose ps" -ForegroundColor White
Write-Host "📋 Logs Langfuse:      docker-compose logs langfuse" -ForegroundColor White
Write-Host "📋 Logs MLOps:         docker-compose logs mlops-app" -ForegroundColor White
Write-Host "🔄 Redémarrer tout:    docker-compose restart" -ForegroundColor White

Write-Host "`n💡 Prochaines étapes:" -ForegroundColor Cyan
Write-Host "1. 🌐 Ouvrez le dashboard: http://localhost:8000/dashboard" -ForegroundColor White
Write-Host "2. 🔍 Configurez Langfuse: http://localhost:3001" -ForegroundColor White
Write-Host "3. 🧪 Testez les inférences avec l'API" -ForegroundColor White
Write-Host "4. 📊 Explorez les métriques dans Grafana" -ForegroundColor White

if ($configContent -match "VOTRE_CLE_OPENAI_ICI") {
    Write-Host "`n⚠️ RAPPEL:" -ForegroundColor Yellow
    Write-Host "Configurez votre clé OpenAI pour activer l'agent IA juge" -ForegroundColor Yellow
}

Write-Host "`n✅ Votre plateforme MLOps avec Langfuse v3 est opérationnelle!" -ForegroundColor Green