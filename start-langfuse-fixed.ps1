# Script de démarrage Langfuse corrigé
param(
    [switch]$Clean = $false
)

Write-Host "=== Démarrage Langfuse Corrigé ===" -ForegroundColor Green

if ($Clean) {
    Write-Host "🧹 Nettoyage complet..." -ForegroundColor Yellow
    docker-compose down -v --remove-orphans
    docker volume prune -f
}

# Étape 1: Démarrer PostgreSQL et ClickHouse
Write-Host "📊 Démarrage des bases de données..." -ForegroundColor Cyan
docker-compose up -d langfuse-postgres clickhouse

Write-Host "⏳ Attente de l'initialisation des bases (30 secondes)..." -ForegroundColor Yellow
Start-Sleep -Seconds 30

# Vérifier ClickHouse
Write-Host "🔍 Vérification ClickHouse..." -ForegroundColor Cyan
try {
    $clickhouseTest = Invoke-WebRequest -Uri "http://localhost:8123/ping" -TimeoutSec 10
    Write-Host "✅ ClickHouse opérationnel" -ForegroundColor Green
} catch {
    Write-Host "❌ ClickHouse non accessible" -ForegroundColor Red
    Write-Host "📋 Logs ClickHouse:" -ForegroundColor Yellow
    docker-compose logs clickhouse --tail 10
}

# Vérifier PostgreSQL Langfuse
Write-Host "🔍 Vérification PostgreSQL Langfuse..." -ForegroundColor Cyan
$pgReady = docker-compose exec -T langfuse-postgres pg_isready -U langfuse -d langfuse
if ($pgReady -match "accepting connections") {
    Write-Host "✅ PostgreSQL Langfuse opérationnel" -ForegroundColor Green
} else {
    Write-Host "❌ PostgreSQL Langfuse non prêt" -ForegroundColor Red
}

# Étape 2: Démarrer Langfuse
Write-Host "🚀 Démarrage de Langfuse..." -ForegroundColor Cyan
docker-compose up -d langfuse

Write-Host "⏳ Attente de l'initialisation de Langfuse (60 secondes)..." -ForegroundColor Yellow
Start-Sleep -Seconds 60

# Vérifier Langfuse
Write-Host "🔍 Vérification Langfuse..." -ForegroundColor Cyan
try {
    $langfuseTest = Invoke-WebRequest -Uri "http://localhost:3001" -TimeoutSec 15
    Write-Host "✅ Langfuse accessible" -ForegroundColor Green
} catch {
    Write-Host "⚠️ Langfuse en cours d'initialisation" -ForegroundColor Yellow
}

# Vérifier les logs Langfuse
Write-Host "📋 Vérification des logs Langfuse..." -ForegroundColor Cyan
$langfuseLogs = docker-compose logs langfuse --tail 15
if ($langfuseLogs -match "CLICKHOUSE_URL is not configured") {
    Write-Host "❌ Problème ClickHouse persistant" -ForegroundColor Red
    Write-Host "🔄 Tentative de redémarrage..." -ForegroundColor Yellow
    docker-compose restart langfuse
    Start-Sleep -Seconds 45
} elseif ($langfuseLogs -match "ready") {
    Write-Host "✅ Langfuse initialisé correctement" -ForegroundColor Green
} else {
    Write-Host "⚠️ Langfuse en cours d'initialisation" -ForegroundColor Yellow
}

# Étape 3: Démarrer le reste
Write-Host "🏠 Démarrage des autres services..." -ForegroundColor Cyan
docker-compose up -d

Write-Host "✅ Tous les services démarrés!" -ForegroundColor Green

# Résumé
Write-Host "`n🎯 Status des services:" -ForegroundColor Cyan
docker-compose ps

Write-Host "`n🌐 Points d'accès:" -ForegroundColor Cyan
Write-Host "🔍 Langfuse:      http://localhost:3001" -ForegroundColor White
Write-Host "🏠 MLOps App:     http://localhost:8000" -ForegroundColor White
Write-Host "📊 Dashboard:     http://localhost:8000/dashboard" -ForegroundColor White
Write-Host "🗄️ ClickHouse:    http://localhost:8123" -ForegroundColor White

Write-Host "`n💡 Si Langfuse a encore des problèmes:" -ForegroundColor Yellow
Write-Host "docker-compose logs langfuse" -ForegroundColor White
Write-Host "docker-compose restart langfuse" -ForegroundColor White