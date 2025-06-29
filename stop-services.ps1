# Script pour arrêter proprement tous les services MLOps
param(
    [switch]$RemoveVolumes = $false
)

Write-Host "=== Arrêt des Services MLOps ===" -ForegroundColor Yellow

# Arrêter tous les services
Write-Host "🛑 Arrêt des conteneurs..." -ForegroundColor Cyan
try {
    if ($RemoveVolumes) {
        docker-compose down -v
        Write-Host "✅ Services arrêtés et volumes supprimés" -ForegroundColor Green
    } else {
        docker-compose down
        Write-Host "✅ Services arrêtés (volumes conservés)" -ForegroundColor Green
    }
} catch {
    Write-Host "⚠️ Erreur lors de l'arrêt: $($_.Exception.Message)" -ForegroundColor Red
}

# Vérifier que tout est arrêté
Write-Host "`n📊 Vérification..." -ForegroundColor Cyan
$containers = docker ps -a --filter "name=mlops" --format "{{.Names}}" 2>$null
if ($containers) {
    Write-Host "⚠️ Conteneurs encore présents:" -ForegroundColor Yellow
    $containers | ForEach-Object { Write-Host "   - $_" -ForegroundColor White }
} else {
    Write-Host "✅ Tous les conteneurs MLOps sont arrêtés" -ForegroundColor Green
}

# Afficher l'utilisation des ports
Write-Host "`n🔌 Ports libérés:" -ForegroundColor Cyan
$ports = @(8000, 3001, 3000, 9090, 5432, 6379, 8123)
foreach ($port in $ports) {
    $connection = Test-NetConnection -ComputerName localhost -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue
    if ($connection) {
        Write-Host "   ⚠️ Port $port encore utilisé" -ForegroundColor Yellow
    } else {
        Write-Host "   ✅ Port $port libéré" -ForegroundColor Green
    }
}

Write-Host "`n✅ Arrêt terminé!" -ForegroundColor Green