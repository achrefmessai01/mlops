@echo off
echo.
echo ==========================================
echo   🔧 MLOps Platform - Commandes Rapides
echo ==========================================
echo.
echo 1. Arreter tous les services
echo 2. Demarrer tous les services  
echo 3. Redemarrer tous les services
echo 4. Voir les logs
echo 5. Generer des donnees de test
echo 6. Ouvrir le dashboard
echo 7. Verifier le statut
echo 8. Quitter
echo.
set /p choice="Choisissez une option (1-8): "

if "%choice%"=="1" goto stop
if "%choice%"=="2" goto start
if "%choice%"=="3" goto restart
if "%choice%"=="4" goto logs
if "%choice%"=="5" goto test
if "%choice%"=="6" goto dashboard
if "%choice%"=="7" goto status
if "%choice%"=="8" goto exit

:stop
echo Arret des services...
powershell -ExecutionPolicy Bypass -File "stop-services.ps1"
pause
goto menu

:start
echo Demarrage des services...
docker-compose up -d
pause
goto menu

:restart
echo Redemarrage des services...
docker-compose restart
pause
goto menu

:logs
echo Affichage des logs...
docker-compose logs -f
goto menu

:test
echo Generation de donnees de test...
powershell -ExecutionPolicy Bypass -File "test_openai_requests_fixed.ps1" -RequestCount 20
pause
goto menu

:dashboard
echo Ouverture du dashboard...
start http://localhost:8000/dashboard
goto menu

:status
echo Verification du statut...
docker-compose ps
curl http://localhost:8000/health
pause
goto menu

:exit
exit