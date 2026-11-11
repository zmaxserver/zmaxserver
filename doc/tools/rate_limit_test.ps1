# ============================================================
# ZMax Server - Token Bucket Rate Limit Stres Testi
# ============================================================
$url = "http://127.0.0.1:19480/index.html"
$successCount = 0
$blockedCount = 0

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "⚡ ZMax Server Rate Limiting & DoS Kalkan Testi..." -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

for ($i = 1; $i -le 2100; $i++) {
    try {
        $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2
        if ($resp.StatusCode -eq 200) {
            $successCount++
        }
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 429) {
            $blockedCount++
            if ($blockedCount -eq 1) {
                Write-Host "`n[*] $i. istekte 429 Too Many Requests kalkanı devreye girdi!" -ForegroundColor Yellow
            }
        }
    }

    if ($i % 200 -eq 0) {
        Write-Host "İstek: $i | 200 OK: $successCount | 429 Engellendi: $blockedCount"
    }
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Test Tamamlandı:"
Write-Host "Kabul Edilen İstek: $successCount" -ForegroundColor Green
Write-Host "Engellenen Saldırı İstekleri: $blockedCount" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan

