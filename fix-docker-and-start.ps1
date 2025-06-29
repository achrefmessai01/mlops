# Script de résolution Docker et démarrage MLOps Platform
param(
    [switch]$Force = $false
)

Write-Host "=== MLOps Platform - Résolution Docker et Démarrage ===" -ForegroundColor Green

# Fonction pour vérifier Docker Desktop
function Test-DockerDesktop {
    try {
        $dockerInfo = docker info 2>$null
        return $true
    }
    catch {
        return $false
    }
}

# Fonction pour démarrer Docker Desktop
function Start-DockerDesktop {
    Write-Host "🔄 Tentative de démarrage de Docker Desktop..." -ForegroundColor Yellow
    
    # Chercher Docker Desktop
    $dockerPaths = @(
        "${env:ProgramFiles}\Docker\Docker\Docker Desktop.exe",
        "${env:ProgramFiles(x86)}\Docker\Docker\Docker Desktop.exe",
        "${env:LOCALAPPDATA}\Programs\Docker\Docker\Docker Desktop.exe"
    )
    
    $dockerPath = $null
    foreach ($path in $dockerPaths) {
        if (Test-Path $path) {
            $dockerPath = $path
            break
        }
    }
    
    if ($dockerPath) {
        Start-Process -FilePath $dockerPath -WindowStyle Hidden
        Write-Host "✅ Docker Desktop en cours de démarrage..." -ForegroundColor Green
        return $true
    } else {
        Write-Host "❌ Docker Desktop non trouvé. Veuillez l'installer." -ForegroundColor Red
        return $false
    }
}

# Étape 1: Vérifier Docker
Write-Host "`n📋 Étape 1: Vérification de Docker" -ForegroundColor Cyan

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Docker n'est pas installé ou pas dans le PATH" -ForegroundColor Red
    Write-Host "💡 Téléchargez Docker Desktop: https://www.docker.com/products/docker-desktop" -ForegroundColor Yellow
    exit 1
}

Write-Host "✅ Docker CLI trouvé" -ForegroundColor Green

# Étape 2: Vérifier Docker Desktop
Write-Host "`n📋 Étape 2: Vérification de Docker Desktop" -ForegroundColor Cyan

if (-not (Test-DockerDesktop)) {
    Write-Host "⚠️ Docker Desktop n'est pas démarré" -ForegroundColor Yellow
    
    if (Start-DockerDesktop) {
        Write-Host "⏳ Attente du démarrage de Docker Desktop (60 secondes)..." -ForegroundColor Yellow
        
        $timeout = 60
        $elapsed = 0
        while ($elapsed -lt $timeout -and -not (Test-DockerDesktop)) {
            Start-Sleep -Seconds 2
            $elapsed += 2
            Write-Host "." -NoNewline -ForegroundColor Yellow
        }
        Write-Host ""
        
        if (Test-DockerDesktop) {
            Write-Host "✅ Docker Desktop démarré avec succès!" -ForegroundColor Green
        } else {
            Write-Host "❌ Docker Desktop n'a pas pu démarrer dans les temps" -ForegroundColor Red
            Write-Host "💡 Démarrez manuellement Docker Desktop et relancez ce script" -ForegroundColor Yellow
            exit 1
        }
    } else {
        exit 1
    }
} else {
    Write-Host "✅ Docker Desktop est actif" -ForegroundColor Green
}

# Étape 3: Vérifier la configuration
Write-Host "`n📋 Étape 3: Vérification de la configuration" -ForegroundColor Cyan

if (-not (Test-Path "app\model_api_keys.env")) {
    Write-Host "❌ Fichier de configuration manquant" -ForegroundColor Red
    Write-Host "💡 Création du fichier de configuration..." -ForegroundColor Yellow
    
    $configContent = @"
# ================================================
# Configuration MLOps Monitoring Platform
# ================================================

# =====================================
# CONFIGURATION DES MODÈLES IA
# =====================================

# OpenRouter API Key (REQUIS pour modèles open source)
OPENROUTER_API_KEY=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

# OpenAI API Key (REQUIS pour GPT-4, GPT-3.5 et Agent IA)
OPENAI_API_KEY=VOTRE_CLE_OPENAI_ICI

# =====================================
# MONITORING ET ANALYTICS
# =====================================

# Langfuse Configuration LOCAL (Monitoring avancé)
LANGFUSE_SECRET_KEY=sk-lf-local-secret-key
LANGFUSE_PUBLIC_KEY=pk-lf-local-public-key
LANGFUSE_HOST=http://localhost:3001

# =====================================
# CONFIGURATION DE SÉCURITÉ
# =====================================

# Seuils de détection de menaces
SECURITY_THRESHOLD_LOW=5
SECURITY_THRESHOLD_MEDIUM=10
SECURITY_THRESHOLD_HIGH=15
SECURITY_THRESHOLD_CRITICAL=20

# Blocage automatique des requêtes critiques
AUTO_BLOCK_CRITICAL_THREATS=true

# =====================================
# SYSTÈME D'ALERTES
# =====================================

# Configuration Email (OPTIONNEL)
ALERT_EMAIL_USER=
ALERT_EMAIL_PASSWORD=
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
ALERT_RECIPIENTS=

# Configuration Slack (OPTIONNEL)
SLACK_WEBHOOK_URL=

# Configuration Teams (OPTIONNEL)
TEAMS_WEBHOOK_URL=

# =====================================
# SEUILS D'ALERTE
# =====================================

ALERT_SECURITY_THRESHOLD=5
ALERT_LATENCY_THRESHOLD=5.0
ALERT_ERROR_RATE_THRESHOLD=0.05
ALERT_ANOMALY_THRESHOLD=3
"@
    
    $configContent | Out-File -FilePath "app\model_api_keys.env" -Encoding UTF8
    Write-Host "✅ Fichier de configuration créé" -ForegroundColor Green
    Write-Host "⚠️ IMPORTANT: Éditez app\model_api_keys.env et ajoutez votre clé OpenAI" -ForegroundColor Yellow
    Write-Host "   Remplacez 'VOTRE_CLE_OPENAI_ICI' par votre vraie clé OpenAI" -ForegroundColor Yellow
}

# Vérifier la clé OpenAI
$configContent = Get-Content "app\model_api_keys.env" -Raw
if ($configContent -match "VOTRE_CLE_OPENAI_ICI" -or $configContent -notmatch "OPENAI_API_KEY=sk-") {
    Write-Host "⚠️ Clé OpenAI non configurée" -ForegroundColor Yellow
    Write-Host "💡 Pour obtenir une clé OpenAI:" -ForegroundColor Cyan
    Write-Host "   1. Allez sur https://platform.openai.com/api-keys" -ForegroundColor White
    Write-Host "   2. Créez un compte ou connectez-vous" -ForegroundColor White
    Write-Host "   3. Cliquez 'Create new secret key'" -ForegroundColor White
    Write-Host "   4. Copiez la clé (format: sk-proj-...)" -ForegroundColor White
    Write-Host "   5. Remplacez VOTRE_CLE_OPENAI_ICI dans app\model_api_keys.env" -ForegroundColor White
    Write-Host "   6. Ajoutez des crédits à votre compte OpenAI (5-10$)" -ForegroundColor White
    
    if (-not $Force) {
        $continue = Read-Host "`nVoulez-vous continuer sans clé OpenAI? (o/n)"
        if ($continue -ne "o") {
            Write-Host "💡 Configurez votre clé OpenAI et relancez le script" -ForegroundColor Yellow
            exit 0
        }
    }
}

Write-Host "✅ Configuration vérifiée" -ForegroundColor Green

# Étape 4: Créer les dossiers nécessaires
Write-Host "`n📋 Étape 4: Création des dossiers" -ForegroundColor Cyan

$folders = @("logs", "data", "exports", "static")
foreach ($folder in $folders) {
    if (-not (Test-Path $folder)) {
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        Write-Host "✅ Dossier $folder créé" -ForegroundColor Green
    }
}

# Étape 5: Nettoyer les anciens conteneurs si nécessaire
Write-Host "`n📋 Étape 5: Nettoyage des anciens conteneurs" -ForegroundColor Cyan

try {
    $containers = docker ps -a --filter "name=mlops" --format "{{.Names}}" 2>$null
    if ($containers) {
        Write-Host "🧹 Arrêt des anciens conteneurs..." -ForegroundColor Yellow
        docker-compose down 2>$null
        Write-Host "✅ Anciens conteneurs arrêtés" -ForegroundColor Green
    }
} catch {
    Write-Host "⚠️ Pas d'anciens conteneurs à nettoyer" -ForegroundColor Yellow
}

# Étape 6: Supprimer la ligne version obsolète
Write-Host "`n📋 Étape 6: Correction du docker-compose.yml" -ForegroundColor Cyan

if (Test-Path "docker-compose.yml") {
    $composeContent = Get-Content "docker-compose.yml"
    $newContent = $composeContent | Where-Object { $_ -notmatch "^version:" }
    $newContent | Set-Content "docker-compose.yml"
    Write-Host "✅ docker-compose.yml corrigé" -ForegroundColor Green
}

# Étape 7: Démarrage des services
Write-Host "`n📋 Étape 7: Démarrage des services" -ForegroundColor Cyan

Write-Host "🚀 Construction et démarrage des conteneurs..." -ForegroundColor Yellow
Write-Host "   (Cela peut prendre 3-5 minutes la première fois)" -ForegroundColor Yellow

try {
    # Démarrer avec build
    $output = docker-compose up --build -d 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Services démarrés avec succès!" -ForegroundColor Green
    } else {
        Write-Host "❌ Erreur lors du démarrage:" -ForegroundColor Red
        Write-Host $output -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "❌ Erreur lors du démarrage: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Étape 8: Vérification des services
Write-Host "`n📋 Étape 8: Vérification des services" -ForegroundColor Cyan

Write-Host "⏳ Attente du démarrage complet (30 secondes)..." -ForegroundColor Yellow
Start-Sleep -Seconds 30

$services = @(
    @{name="MLOps App"; url="http://localhost:8000/health"},
    @{name="Langfuse"; url="http://localhost:3001"},
    @{name="Grafana"; url="http://localhost:3000"},
    @{name="Prometheus"; url="http://localhost:9090"}
)

foreach ($service in $services) {
    try {
        $response = Invoke-WebRequest -Uri $service.url -TimeoutSec 10 -UseBasicParsing
        Write-Host "✅ $($service.name) - OK" -ForegroundColor Green
    } catch {
        Write-Host "⚠️ $($service.name) - En cours de démarrage..." -ForegroundColor Yellow
    }
}

# Étape 9: Génération de données de test
Write-Host "`n📋 Étape 9: Génération de données de test" -ForegroundColor Cyan

if (Test-Path "test_openai_requests.ps1") {
    Write-Host "🧪 Génération de données de test..." -ForegroundColor Yellow
    try {
        & .\test_openai_requests.ps1 -RequestCount 15
        Write-Host "✅ Données de test générées" -ForegroundColor Green
    } catch {
        Write-Host "⚠️ Erreur lors de la génération de test: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "⚠️ Script de test non trouvé" -ForegroundColor Yellow
}

# Résumé final
Write-Host "`n🎉 DÉMARRAGE TERMINÉ!" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green

Write-Host "`n🌐 Points d'accès:" -ForegroundColor Cyan
Write-Host "🏠 Application:    http://localhost:8000" -ForegroundColor White
Write-Host "📊 Dashboard:      http://localhost:8000/dashboard" -ForegroundColor White
Write-Host "📖 API Docs:       http://localhost:8000/docs" -ForegroundColor White
Write-Host "🔍 Langfuse:       http://localhost:3001" -ForegroundColor White
Write-Host "📈 Grafana:        http://localhost:3000 (admin/admin123)" -ForegroundColor White
Write-Host "📊 Prometheus:     http://localhost:9090" -ForegroundColor White

Write-Host "`n💡 Prochaines étapes:" -ForegroundColor Cyan
Write-Host "1. Ouvrez le dashboard: http://localhost:8000/dashboard" -ForegroundColor White
Write-Host "2. Configurez Langfuse (première visite): http://localhost:3001" -ForegroundColor White
Write-Host "3. Testez une inférence via l'API ou le dashboard" -ForegroundColor White
Write-Host "4. Explorez les métriques dans Grafana" -ForegroundColor White

Write-Host "`n🔧 Commandes utiles:" -ForegroundColor Cyan
Write-Host "📊 Voir les logs:     docker-compose logs -f" -ForegroundColor White
Write-Host "🔄 Redémarrer:        docker-compose restart" -ForegroundColor White
Write-Host "🛑 Arrêter:           docker-compose down" -ForegroundColor White
Write-Host "🧪 Tests:             .\test_openai_requests.ps1" -ForegroundColor White

if ($configContent -match "VOTRE_CLE_OPENAI_ICI") {
    Write-Host "`n⚠️ RAPPEL IMPORTANT:" -ForegroundColor Yellow
    Write-Host "Configurez votre clé OpenAI dans app\model_api_keys.env" -ForegroundColor Yellow
    Write-Host "pour activer l'agent IA juge et les modèles GPT-4/GPT-3.5" -ForegroundColor Yellow
}

Write-Host "`n✅ Votre plateforme MLOps est prête!" -ForegroundColor Green
