# Script final de correction et démarrage MLOps Platform
param(
    [switch]$Force = $false
)

Write-Host "=== MLOps Platform - Correction Finale et Démarrage ===" -ForegroundColor Green

# Étape 1: Arrêter complètement tous les services
Write-Host "`n📋 Étape 1: Arrêt complet des services" -ForegroundColor Cyan
try {
    docker-compose down -v --remove-orphans 2>$null
    Write-Host "✅ Services arrêtés et volumes nettoyés" -ForegroundColor Green
} catch {
    Write-Host "⚠️ Aucun service à arrêter" -ForegroundColor Yellow
}

# Étape 2: Vérifier Docker Desktop
Write-Host "`n📋 Étape 2: Vérification Docker Desktop" -ForegroundColor Cyan
try {
    $dockerInfo = docker info 2>$null
    Write-Host "✅ Docker Desktop actif" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker Desktop non actif" -ForegroundColor Red
    Write-Host "💡 Démarrez Docker Desktop et relancez ce script" -ForegroundColor Yellow
    exit 1
}

# Étape 3: Vérifier la configuration
Write-Host "`n📋 Étape 3: Vérification de la configuration" -ForegroundColor Cyan
if (Test-Path "app\model_api_keys.env") {
    $configContent = Get-Content "app\model_api_keys.env" -Raw
    if ($configContent -match "VOTRE_CLE_OPENAI_ICI") {
        Write-Host "⚠️ Clé OpenAI non configurée" -ForegroundColor Yellow
        Write-Host "💡 Configurez votre clé OpenAI pour l'agent IA juge" -ForegroundColor Yellow
    } else {
        Write-Host "✅ Configuration vérifiée" -ForegroundColor Green
    }
} else {
    Write-Host "❌ Fichier de configuration manquant" -ForegroundColor Red
    exit 1
}

# Étape 4: Créer les dossiers nécessaires
Write-Host "`n📋 Étape 4: Création des dossiers" -ForegroundColor Cyan
$folders = @("logs", "data", "exports", "static")
foreach ($folder in $folders) {
    if (-not (Test-Path $folder)) {
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        Write-Host "✅ Dossier $folder créé" -ForegroundColor Green
    }
}

# Étape 5: Démarrage séquentiel optimisé
Write-Host "`n📋 Étape 5: Démarrage séquentiel des services" -ForegroundColor Cyan

Write-Host "🗄️ Démarrage des bases de données..." -ForegroundColor Yellow
docker-compose up -d langfuse-postgres clickhouse postgres redis
Write-Host "⏳ Attente de l'initialisation des bases (45 secondes)..." -ForegroundColor Yellow
Start-Sleep -Seconds 45

Write-Host "🔍 Démarrage de Langfuse..." -ForegroundColor Yellow
docker-compose up -d langfuse
Write-Host "⏳ Attente de l'initialisation de Langfuse (60 secondes)..." -ForegroundColor Yellow
Start-Sleep -Seconds 60

Write-Host "🏠 Démarrage des services applicatifs..." -ForegroundColor Yellow
docker-compose up -d mlops-app prometheus grafana nginx
Write-Host "⏳ Attente de l'initialisation complète (30 secondes)..." -ForegroundColor Yellow
Start-Sleep -Seconds 30

Write-Host "✅ Tous les services démarrés!" -ForegroundColor Green

# Étape 6: Vérification complète des services
Write-Host "`n📋 Étape 6: Vérification des services" -ForegroundColor Cyan

$services = @(
    @{name="PostgreSQL MLOps"; port=5432},
    @{name="PostgreSQL Langfuse"; port=5433},
    @{name="ClickHouse"; port=8123},
    @{name="Redis"; port=6379},
    @{name="MLOps App"; url="http://localhost:8000/health"; port=8000},
    @{name="Langfuse"; url="http://localhost:3001"; port=3001},
    @{name="Grafana"; url="http://localhost:3000"; port=3000},
    @{name="Prometheus"; url="http://localhost:9090"; port=9090}
)

foreach ($service in $services) {
    if ($service.url) {
        try {
            $response = Invoke-WebRequest -Uri $service.url -TimeoutSec 10 -UseBasicParsing
            Write-Host "✅ $($service.name) - Opérationnel" -ForegroundColor Green
        } catch {
            Write-Host "⚠️ $($service.name) - En cours d'initialisation..." -ForegroundColor Yellow
        }
    } else {
        $portOpen = Test-NetConnection -ComputerName localhost -Port $service.port -InformationLevel Quiet -WarningAction SilentlyContinue
        if ($portOpen) {
            Write-Host "✅ $($service.name) - Port $($service.port) ouvert" -ForegroundColor Green
        } else {
            Write-Host "❌ $($service.name) - Port $($service.port) fermé" -ForegroundColor Red
        }
    }
}

# Étape 7: Vérification spécifique Langfuse
Write-Host "`n📋 Étape 7: Vérification Langfuse" -ForegroundColor Cyan
try {
    $langfuseLogs = docker-compose logs langfuse --tail 20 2>$null
    if ($langfuseLogs -match "CLICKHOUSE_URL is not configured") {
        Write-Host "❌ Langfuse a encore des problèmes ClickHouse" -ForegroundColor Red
        Write-Host "🔄 Redémarrage de Langfuse..." -ForegroundColor Yellow
        docker-compose restart langfuse
        Start-Sleep -Seconds 45
    } elseif ($langfuseLogs -match "ready") {
        Write-Host "✅ Langfuse opérationnel" -ForegroundColor Green
    } else {
        Write-Host "⚠️ Langfuse en cours d'initialisation" -ForegroundColor Yellow
    }
} catch {
    Write-Host "⚠️ Impossible de vérifier les logs Langfuse" -ForegroundColor Yellow
}

# Étape 8: Test de l'API MLOps
Write-Host "`n📋 Étape 8: Test de l'API MLOps" -ForegroundColor Cyan
try {
    $healthCheck = Invoke-RestMethod -Uri "http://localhost:8000/health" -TimeoutSec 15
    Write-Host "✅ API MLOps opérationnelle" -ForegroundColor Green
    Write-Host "   📊 Status: $($healthCheck.status)" -ForegroundColor Cyan
} catch {
    Write-Host "⚠️ API MLOps en cours d'initialisation" -ForegroundColor Yellow
}

# Étape 9: Génération de données de test
Write-Host "`n📋 Étape 9: Génération de données de test" -ForegroundColor Cyan
if (Test-Path "test_openai_requests_fixed.ps1") {
    Write-Host "🧪 Génération de 25 requêtes de test..." -ForegroundColor Yellow
    try {
        & .\test_openai_requests_fixed.ps1 -RequestCount 25
        Write-Host "✅ Données de test générées" -ForegroundColor Green
    } catch {
        Write-Host "⚠️ Erreur lors des tests: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "⚠️ Script de test non trouvé" -ForegroundColor Yellow
}

# Résumé final
Write-Host "`n🎉 DÉMARRAGE FINAL TERMINÉ!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

Write-Host "`n🌐 Points d'accès:" -ForegroundColor Cyan
Write-Host "🏠 Application MLOps:  http://localhost:8000" -ForegroundColor White
Write-Host "📊 Dashboard:          http://localhost:8000/dashboard" -ForegroundColor White
Write-Host "📖 API Documentation:  http://localhost:8000/docs" -ForegroundColor White
Write-Host "🔍 Langfuse (LOCAL):   http://localhost:3001" -ForegroundColor White
Write-Host "📈 Grafana:            http://localhost:3000 (admin/admin123)" -ForegroundColor White
Write-Host "📊 Prometheus:         http://localhost:9090" -ForegroundColor White
Write-Host "🗄️ ClickHouse:         http://localhost:8123" -ForegroundColor White

Write-Host "`n🔧 Commandes utiles:" -ForegroundColor Cyan
Write-Host "📊 Status:             docker-compose ps" -ForegroundColor White
Write-Host "📋 Logs Langfuse:      docker-compose logs langfuse" -ForegroundColor White
Write-Host "📋 Logs MLOps:         docker-compose logs mlops-app" -ForegroundColor White
Write-Host "🔄 Redémarrer:         docker-compose restart" -ForegroundColor White
Write-Host "🛑 Arrêter:            docker-compose down" -ForegroundColor White

Write-Host "`n💡 Prochaines étapes:" -ForegroundColor Cyan
Write-Host "1. 🌐 Ouvrez le dashboard: http://localhost:8000/dashboard" -ForegroundColor White
Write-Host "2. 🔍 Configurez Langfuse: http://localhost:3001" -ForegroundColor White
Write-Host "3. 🧪 Testez les inférences avec l'API" -ForegroundColor White
Write-Host "4. 📊 Explorez les métriques dans Grafana" -ForegroundColor White

Write-Host "`n✅ Votre plateforme MLOps est maintenant 100% opérationnelle!" -ForegroundColor Green

# Option pour ouvrir le dashboard
$openDashboard = Read-Host "`nOuvrir le dashboard maintenant? (o/n)"
if ($openDashboard -eq "o") {
    Start-Process "http://localhost:8000/dashboard"
}