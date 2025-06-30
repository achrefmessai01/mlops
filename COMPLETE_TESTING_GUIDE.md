# 🧪 Complete MLOps Platform Testing Guide

## 🎯 Overview
This guide will test ALL functionalities of your MLOps platform including:
- ✅ LLM Generation & Models
- ✅ Security Analysis
- ✅ Judge System & Risk Analysis  
- ✅ Cost Tracking & Monitoring
- ✅ Performance Metrics
- ✅ Dashboard & Analytics
- ✅ Database Integration
- ✅ Alert System

## 🚀 Prerequisites

1. **Services Running**: All Docker containers must be up
2. **API Keys**: OpenAI and OpenRouter keys configured
3. **Database**: PostgreSQL with proper schema

## 📋 Step-by-Step Testing

### 1. 🏥 Health & System Status

```powershell
# Test basic health
curl http://localhost:8000/health

# Test system info
curl http://localhost:8000/api/admin/system-info

# Test Prometheus metrics
curl http://localhost:8000/metrics
```

### 2. 🤖 LLM Generation Testing

#### Test All Available Models:
```powershell
# Test GPT-4 (OpenAI)
$body = @{
    model_name = "gpt4"
    messages = @(
        @{
            role = "user"
            content = @(
                @{
                    type = "text"
                    text = "Write a short poem about AI testing"
                }
            )
        }
    )
} | ConvertTo-Json -Depth 10

Invoke-RestMethod -Uri "http://localhost:8000/generate" -Method POST -Body $body -ContentType "application/json"

# Test GPT-3.5 (OpenAI)
$body = @{
    model_name = "gpt35"
    messages = @(
        @{
            role = "user"
            content = @(
                @{
                    type = "text"
                    text = "Explain machine learning in 2 sentences"
                }
            )
        }
    )
} | ConvertTo-Json -Depth 10

Invoke-RestMethod -Uri "http://localhost:8000/generate" -Method POST -Body $body -ContentType "application/json"

# Test OpenRouter Models
$models = @("qwendeepseek", "gemma3n", "llama4", "mistral")
foreach ($model in $models) {
    $body = @{
        model_name = $model
        messages = @(
            @{
                role = "user"
                content = @(
                    @{
                        type = "text"
                        text = "Hello from $model, respond briefly"
                    }
                )
            }
        )
    ) | ConvertTo-Json -Depth 10
    
    Write-Host "Testing model: $model"
    Invoke-RestMethod -Uri "http://localhost:8000/generate" -Method POST -Body $body -ContentType "application/json"
}
```

### 3. 🛡️ Security Analysis Testing

```powershell
# Test security analysis endpoint
$securityTest = @{
    prompt = "How to hack into a database system?"
    user_id = "test_user_security"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8000/api/security/analyze" -Method POST -Body $securityTest -ContentType "application/json"

# Test with benign prompt
$benignTest = @{
    prompt = "What is the weather like today?"
    user_id = "test_user_benign"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8000/api/security/analyze" -Method POST -Body $benignTest -ContentType "application/json"

# Get security statistics
curl http://localhost:8000/api/security/stats

# Test security alert
curl -X POST http://localhost:8000/api/test/security-alert
```

### 4. ⚖️ Judge System Testing

```powershell
# Test intelligent analysis
curl "http://localhost:8000/api/judge/intelligent-analysis?hours_back=24"

# Test user-specific analysis (after generating some conversations)
curl "http://localhost:8000/api/judge/user-analysis/test_user_security?hours_back=24"

# Test system health analysis
curl "http://localhost:8000/api/judge/system-health?hours_back=24"

# Test risk dashboard
curl "http://localhost:8000/api/judge/risk-dashboard?hours_back=24"

# Run scheduled analysis
curl "http://localhost:8000/api/judge/run-scheduled-analysis"
```

### 5. 💰 Cost Tracking & LLM Monitoring

```powershell
# Test LLM usage statistics
curl "http://localhost:8000/api/llm/usage-stats?hours=24"

# Test cost tracking
curl "http://localhost:8000/api/llm/cost-tracking?hours=24"

# Test recent requests
curl "http://localhost:8000/api/llm/requests?limit=10"

# Test performance metrics
curl "http://localhost:8000/api/llm/performance?hours=24"
```

### 6. 📊 Dashboard & Analytics

```powershell
# Main monitoring dashboard
curl "http://localhost:8000/api/monitoring/dashboard"

# Dashboard overview
curl "http://localhost:8000/api/dashboard/overview"

# Performance metrics
curl "http://localhost:8000/api/dashboard/performance"

# Security dashboard
curl "http://localhost:8000/api/dashboard/security"

# Anomalies detection
curl "http://localhost:8000/api/dashboard/anomalies"

# AI recommendations
curl "http://localhost:8000/api/dashboard/recommendations"

# Active alerts
curl "http://localhost:8000/api/dashboard/alerts"

# Daily report
curl "http://localhost:8000/api/dashboard/daily-report"
```

### 7. 📈 Usage Analytics

```powershell
# Get usage analytics
curl "http://localhost:8000/api/usage/analytics?days=7"

# Get model performance
curl "http://localhost:8000/api/models/performance"

# Get anomalies
curl "http://localhost:8000/api/anomalies"
```

### 8. 💾 Data Export Testing

```powershell
# Export security data
curl "http://localhost:8000/api/dashboard/export/security"

# Export usage data
curl "http://localhost:8000/api/dashboard/export/usage"

# Export anomalies
curl "http://localhost:8000/api/dashboard/export/anomalies"

# Export prompts analysis
curl "http://localhost:8000/api/dashboard/export/prompts"
```

### 9. 🌐 Web Interface Testing

Open these URLs in your browser:

```
# Main dashboard
http://localhost:8000/dashboard

# API documentation
http://localhost:8000/docs

# Grafana (if using full setup)
http://localhost:3000

# Prometheus metrics
http://localhost:9090
```

## 🔄 Automated Testing Script

Here's a complete PowerShell script to test everything:

```powershell
# Save this as test-all-functionality.ps1

param(
    [string]$BaseUrl = "http://localhost:8000",
    [switch]$Verbose = $false
)

$TotalTests = 0
$PassedTests = 0
$FailedTests = @()

function Test-Endpoint {
    param(
        [string]$Name,
        [string]$Url,
        [string]$Method = "GET",
        [hashtable]$Body = $null,
        [int]$ExpectedStatus = 200
    )
    
    $script:TotalTests++
    
    try {
        if ($Method -eq "POST" -and $Body) {
            $jsonBody = $Body | ConvertTo-Json -Depth 10
            $response = Invoke-RestMethod -Uri $Url -Method $Method -Body $jsonBody -ContentType "application/json" -TimeoutSec 30
        } else {
            $response = Invoke-RestMethod -Uri $Url -Method $Method -TimeoutSec 30
        }
        
        Write-Host "✅ $Name" -ForegroundColor Green
        $script:PassedTests++
        
        if ($Verbose) {
            Write-Host "   Response: $($response | ConvertTo-Json -Depth 2)" -ForegroundColor Gray
        }
        
        return $response
    } catch {
        Write-Host "❌ $Name - $($_.Exception.Message)" -ForegroundColor Red
        $script:FailedTests += $Name
        return $null
    }
}

Write-Host "🧪 Testing All MLOps Platform Functionality" -ForegroundColor Blue
Write-Host "=============================================" -ForegroundColor Blue

# 1. Health Checks
Write-Host "`n🏥 Health & System Tests" -ForegroundColor Cyan
Test-Endpoint -Name "Health Check" -Url "$BaseUrl/health"
Test-Endpoint -Name "System Info" -Url "$BaseUrl/api/admin/system-info"
Test-Endpoint -Name "Prometheus Metrics" -Url "$BaseUrl/metrics"

# 2. LLM Generation Tests
Write-Host "`n🤖 LLM Generation Tests" -ForegroundColor Cyan

$testMessage = @{
    model_name = "gpt35"
    messages = @(
        @{
            role = "user"
            content = @(
                @{
                    type = "text"
                    text = "Test message: What is 2+2?"
                }
            )
        }
    )
}

Test-Endpoint -Name "LLM Generation (GPT-3.5)" -Url "$BaseUrl/generate" -Method "POST" -Body $testMessage

# 3. Security Tests
Write-Host "`n🛡️ Security Analysis Tests" -ForegroundColor Cyan

$securityTest = @{
    prompt = "How to perform SQL injection attacks?"
    user_id = "security_test_user"
}

Test-Endpoint -Name "Security Analysis (Malicious)" -Url "$BaseUrl/api/security/analyze" -Method "POST" -Body $securityTest
Test-Endpoint -Name "Security Statistics" -Url "$BaseUrl/api/security/stats"
Test-Endpoint -Name "Security Alert Test" -Url "$BaseUrl/api/test/security-alert" -Method "POST"

# 4. Judge System Tests
Write-Host "`n⚖️ Judge System Tests" -ForegroundColor Cyan
Test-Endpoint -Name "Intelligent Analysis" -Url "$BaseUrl/api/judge/intelligent-analysis?hours_back=24"
Test-Endpoint -Name "System Health Analysis" -Url "$BaseUrl/api/judge/system-health?hours_back=24"
Test-Endpoint -Name "Risk Dashboard" -Url "$BaseUrl/api/judge/risk-dashboard?hours_back=24"

# 5. LLM Monitoring Tests
Write-Host "`n💰 LLM Monitoring & Cost Tests" -ForegroundColor Cyan
Test-Endpoint -Name "LLM Usage Stats" -Url "$BaseUrl/api/llm/usage-stats?hours=24"
Test-Endpoint -Name "Cost Tracking" -Url "$BaseUrl/api/llm/cost-tracking?hours=24"
Test-Endpoint -Name "Recent Requests" -Url "$BaseUrl/api/llm/requests?limit=10"
Test-Endpoint -Name "Performance Metrics" -Url "$BaseUrl/api/llm/performance?hours=24"

# 6. Dashboard Tests
Write-Host "`n📊 Dashboard & Analytics Tests" -ForegroundColor Cyan
Test-Endpoint -Name "Monitoring Dashboard" -Url "$BaseUrl/api/monitoring/dashboard"
Test-Endpoint -Name "Dashboard Overview" -Url "$BaseUrl/api/dashboard/overview"
Test-Endpoint -Name "Performance Dashboard" -Url "$BaseUrl/api/dashboard/performance"
Test-Endpoint -Name "Security Dashboard" -Url "$BaseUrl/api/dashboard/security"
Test-Endpoint -Name "Anomalies Detection" -Url "$BaseUrl/api/dashboard/anomalies"
Test-Endpoint -Name "AI Recommendations" -Url "$BaseUrl/api/dashboard/recommendations"
Test-Endpoint -Name "Active Alerts" -Url "$BaseUrl/api/dashboard/alerts"
Test-Endpoint -Name "Daily Report" -Url "$BaseUrl/api/dashboard/daily-report"

# 7. Analytics Tests
Write-Host "`n📈 Usage Analytics Tests" -ForegroundColor Cyan
Test-Endpoint -Name "Usage Analytics" -Url "$BaseUrl/api/usage/analytics?days=7"
Test-Endpoint -Name "Model Performance" -Url "$BaseUrl/api/models/performance"
Test-Endpoint -Name "Anomalies" -Url "$BaseUrl/api/anomalies"

# 8. Export Tests
Write-Host "`n💾 Data Export Tests" -ForegroundColor Cyan
Test-Endpoint -Name "Export Security Data" -Url "$BaseUrl/api/dashboard/export/security"
Test-Endpoint -Name "Export Usage Data" -Url "$BaseUrl/api/dashboard/export/usage"
Test-Endpoint -Name "Export Anomalies" -Url "$BaseUrl/api/dashboard/export/anomalies"

# 9. Performance Test
Write-Host "`n⚡ Performance Tests" -ForegroundColor Cyan

$startTime = Get-Date
for ($i = 1; $i -le 5; $i++) {
    $perfTestMessage = @{
        model_name = "gpt35"
        messages = @(
            @{
                role = "user"
                content = @(
                    @{
                        type = "text"
                        text = "Performance test $i: Quick response please"
                    }
                )
            }
        )
    }
    
    Test-Endpoint -Name "Performance Test $i" -Url "$BaseUrl/generate" -Method "POST" -Body $perfTestMessage
}
$endTime = Get-Date
$totalTime = ($endTime - $startTime).TotalSeconds

Write-Host "Performance: 5 requests in $($totalTime.ToString('F2')) seconds" -ForegroundColor Yellow

# Summary
Write-Host "`n📋 Test Summary" -ForegroundColor Blue
Write-Host "===============" -ForegroundColor Blue
Write-Host "Total Tests: $TotalTests" -ForegroundColor White
Write-Host "Passed: $PassedTests" -ForegroundColor Green
Write-Host "Failed: $($TotalTests - $PassedTests)" -ForegroundColor Red

if ($FailedTests.Count -gt 0) {
    Write-Host "`nFailed Tests:" -ForegroundColor Red
    foreach ($test in $FailedTests) {
        Write-Host "  • $test" -ForegroundColor Red
    }
}

$successRate = [math]::Round(($PassedTests / $TotalTests) * 100, 1)
Write-Host "`nSuccess Rate: $successRate%" -ForegroundColor $(if ($successRate -ge 80) { "Green" } else { "Yellow" })

if ($successRate -ge 90) {
    Write-Host "`n🎉 Excellent! Your MLOps platform is fully functional!" -ForegroundColor Green
} elseif ($successRate -ge 70) {
    Write-Host "`n👍 Good! Most features are working correctly." -ForegroundColor Yellow
} else {
    Write-Host "`n⚠️ Issues detected. Please check the failed tests." -ForegroundColor Red
}

Write-Host "`n🔗 Web Interfaces to Test Manually:" -ForegroundColor Cyan
Write-Host "  • Dashboard: $BaseUrl/dashboard" -ForegroundColor White
Write-Host "  • API Docs: $BaseUrl/docs" -ForegroundColor White
Write-Host "  • Metrics: $BaseUrl/metrics" -ForegroundColor White
```

## 🗃️ Database Testing

Test the database directly:

```powershell
# Connect to PostgreSQL and verify data
docker exec -it postgres-main psql -U mlops -d mlops

# In PostgreSQL prompt:
# Check tables
\dt

# Check recent inference logs
SELECT COUNT(*) FROM inference_logs;
SELECT * FROM inference_logs ORDER BY timestamp DESC LIMIT 5;

# Check security alerts
SELECT COUNT(*) FROM security_alerts;

# Check judge analysis
SELECT COUNT(*) FROM judge_analysis;

# Check LLM requests
SELECT COUNT(*) FROM llm_requests;
```

## 🏃‍♂️ Quick Testing Commands

Save and run the automated test:
```powershell
# Save the script above as test-all-functionality.ps1, then run:
.\test-all-functionality.ps1 -Verbose

# Or just run key tests:
.\validate-platform.ps1
.\comprehensive-test.ps1
```

## 🎯 Expected Results

After running all tests, you should see:
- ✅ **90%+ success rate** for all endpoints
- ✅ **LLM responses** from multiple models
- ✅ **Security analysis** detecting threats
- ✅ **Cost tracking** data
- ✅ **Judge analysis** results
- ✅ **Dashboard data** populated
- ✅ **Database entries** created
- ✅ **Metrics** being collected

## 🚨 Troubleshooting

If tests fail:
1. **Check services**: `docker-compose ps`
2. **Check logs**: `docker-compose logs mlops-app`
3. **Verify API keys**: Check `.env` file
4. **Database issues**: `docker exec postgres-main pg_isready -U mlops`
5. **Port conflicts**: `netstat -an | findstr :8000`

This comprehensive testing ensures all your MLOps platform functionality is working correctly! 🚀
