@echo off
cls
echo.
echo ==========================================
echo   🚀 MLOps Platform - Démarrage Rapide
echo ==========================================
echo.

REM Exécuter le script PowerShell de résolution
powershell -ExecutionPolicy Bypass -File "fix-docker-and-start.ps1"

if errorlevel 1 (
    echo.
    echo ❌ Erreur lors du démarrage
    echo 💡 Vérifiez que Docker Desktop est installé et démarré
    pause
    exit /b 1
)

echo.
echo 🎉 Démarrage terminé avec succès!
echo.
set /p open_dashboard="Ouvrir le dashboard? (o/n): "
if /i "%open_dashboard%"=="o" (
    start http://localhost:8000/dashboard
)

echo.
pause