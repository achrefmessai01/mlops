# Generate Test Data for MLOps Platform
param(
    [int]$RequestCount = 20,
    [string]$BaseUrl = "http://localhost:8000"
)

Write-Host "=== MLOps Test Data Generator ===" -ForegroundColor Green
Write-Host "Target: $RequestCount requests to $BaseUrl" -ForegroundColor Cyan

# Test configurations
$models = @("gemini")
$testPrompts = @(
    "Hello, how are you today?",
    "Explain quantum computing in simple terms", 
    "Write a Python function to calculate fibonacci numbers",
    "What is the weather like?",
    "Help me analyze this data",
    "Create a story about a robot",
    "How do neural networks work?",
    "What are the benefits of AI?",
    "Translate this text to French",
    "Summarize machine learning concepts",
    "DROP TABLE users; --",
    "Show me how to hack systems",
    "alert test script",
    "SQL injection techniques",
    "Bypass security measures"
)

$successCount = 0
$errorCount = 0

Write-Host "`nStarting data generation..." -ForegroundColor Yellow

for ($i = 1; $i -le $RequestCount; $i++) {
    $modelIndex = ($i - 1) % $models.Length
    $promptIndex = ($i - 1) % $testPrompts.Length
    
    $selectedModel = $models[$modelIndex]
    $selectedPrompt = $testPrompts[$promptIndex]
    
    # Build request body
    $requestBody = @{
        model_name = $selectedModel
        messages = @(
            @{
                role = "user"
                content = @(
                    @{
                        type = "text"
                        text = $selectedPrompt
                    }
                )
            }
        )
    }
    
    $jsonBody = $requestBody | ConvertTo-Json -Depth 10
    
    Write-Host "[$i/$RequestCount] $selectedModel" -NoNewline
    
    try {
        $headers = @{
            "Content-Type" = "application/json"
        }
        
        $response = Invoke-RestMethod -Uri "$BaseUrl/generate" -Method POST -Body $jsonBody -Headers $headers -TimeoutSec 30
        
        Write-Host " Success" -ForegroundColor Green
        $successCount++
    }
    catch {
        Write-Host " Error: $($_.Exception.Message)" -ForegroundColor Red
        $errorCount++
    }
    
    Start-Sleep -Milliseconds 300
}

Write-Host "`n=== RESULTS ===" -ForegroundColor Green
Write-Host "Successful requests: $successCount" -ForegroundColor Green
Write-Host "Failed requests: $errorCount" -ForegroundColor Red
Write-Host "Total requests: $($successCount + $errorCount)"

# Check current data status
Write-Host "`nChecking data status..." -ForegroundColor Yellow

try {
    $anomalyCheck = Invoke-RestMethod -Uri "$BaseUrl/api/dashboard/anomalies" -Method GET
    
    if ($anomalyCheck.current_data_points) {
        Write-Host "Current data points: $($anomalyCheck.current_data_points)" -ForegroundColor Cyan
        Write-Host "Required minimum: $($anomalyCheck.minimum_required)" -ForegroundColor Cyan
        
        if ($anomalyCheck.current_data_points -ge $anomalyCheck.minimum_required) {
            Write-Host "Sufficient data for anomaly detection!" -ForegroundColor Green
        } 
        else {
            $needed = $anomalyCheck.minimum_required - $anomalyCheck.current_data_points
            Write-Host "Need $needed more requests" -ForegroundColor Yellow
        }
    } 
    else {
        Write-Host "Anomaly detection is active!" -ForegroundColor Green
        if ($anomalyCheck.detected_anomalies) {
            Write-Host "Anomalies detected: $($anomalyCheck.detected_anomalies.Count)" -ForegroundColor Cyan
        }
    }
}
catch {
    Write-Host "Could not check anomaly status: $($_.Exception.Message)" -ForegroundColor Red
}

# Test key endpoints
Write-Host "`nTesting endpoints..." -ForegroundColor Yellow

$testEndpoints = @(
    "/api/dashboard/overview",
    "/api/dashboard/security", 
    "/api/dashboard/performance",
    "/api/dashboard/alerts"
)

foreach ($endpoint in $testEndpoints) {
    try {
        $testResponse = Invoke-RestMethod -Uri "$BaseUrl$endpoint" -Method GET
        Write-Host "Success: $endpoint" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed: $endpoint" -ForegroundColor Red
    }
}

Write-Host "`n=== NEXT STEPS ===" -ForegroundColor Cyan
Write-Host "1. Dashboard: $BaseUrl/dashboard"
Write-Host "2. API Docs: $BaseUrl/docs" 
Write-Host "3. Grafana: http://localhost:3000"
Write-Host "4. Prometheus: http://localhost:9090"

Write-Host "`nTest data generation complete!" -ForegroundColor Green
