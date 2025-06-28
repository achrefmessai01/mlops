@echo off
cls
echo.
echo ==========================================
echo   🚀 MLOps Platform - Quick Start
echo ==========================================
echo.

REM Vérifier Docker
docker --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker n'est pas installé
    pause
    exit /b 1
)

echo ✅ Docker détecté
echo.

REM Vérifier la configuration
if not exist "app\model_api_keys.env" (
    echo ❌ Configuration manquante
    echo 💡 Copiez app\model_api_keys.env.example vers app\model_api_keys.env
    echo    et configurez vos clés API
    pause
    exit /b 1
)

echo ✅ Configuration trouvée
echo.

REM Créer les répertoires nécessaires
if not exist "logs" mkdir logs
if not exist "data" mkdir data
if not exist "exports" mkdir exports

echo 🔄 Construction et démarrage...
docker compose up --build -d

if errorlevel 1 (
    echo ❌ Erreur lors du démarrage
    pause
    exit /b 1
)

echo.
echo ✅ Application démarrée avec succès !
echo.
echo 🌐 Accès:
echo   📱 Application: http://localhost:8000
echo   📊 Dashboard:   http://localhost:8000/dashboard
echo   📖 API Docs:    http://localhost:8000/docs
echo   🔍 Health:      http://localhost:8000/health
echo.
echo 💡 Attendez 30 secondes avant d'accéder aux URLs
echo.

set /p open_browser="Ouvrir le dashboard? (o/n): "
if /i "%open_browser%"=="o" (
    timeout /t 3 /nobreak >nul
    start http://localhost:8000/dashboard
)

echo.
echo 🔧 Commandes utiles:
echo   📊 Logs:    docker compose logs -f
echo   🔄 Restart: docker compose restart
echo   🛑 Stop:    docker compose down
echo.
pause
