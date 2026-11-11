# ============================================================
# ZMax Server - Slowloris Güvenlik Denetim Aracı
# ============================================================
$targetHost = "127.0.0.1"
$targetPort = 19480

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "⚡ ZMax Server Slowloris DoS Kalkan Testi Baslatiliyor..." -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

try {
    $client = New-Object System.Net.Sockets.TcpClient($targetHost, $targetPort)
    $stream = $client.GetStream()
    $writer = New-Object System.IO.StreamWriter($stream)

    # Kısmi başlık gönder (istek tamamlanmadı, asılı bırakılıyor)
    $writer.Write("GET /index.html HTTP/1.1`r`n")
    $writer.Write("Host: $targetHost`r`n")
    $writer.Write("User-Agent: Mozilla/5.0 (Slowloris-Audit)`r`n")
    $writer.Flush()

    Write-Host "[*] Soket açıldı ve kısmi başlık gönderildi." -ForegroundColor Yellow
    Write-Host "[*] ZMax timeout süresi (10s) bekleniyor..." -ForegroundColor Yellow

    for ($i = 1; $i -le 12; $i++) {
        Start-Sleep -Seconds 1
        Write-Host "    $i. saniye..." -NoNewline
        try {
            $writer.Write("X-Slow-$i: $i`r`n")
            $writer.Flush()
            Write-Host " [Veri Gönderildi]" -ForegroundColor DarkGray
        } catch {
            Write-Host " [BAĞLANTI KAPATILDI!]" -ForegroundColor Green
            Write-Host "`n✅ BAŞARILI: ZMax Server Slowloris kalkanı ($i. saniyede) saldırgan soketi kapattı!" -ForegroundColor Green
            exit 0
        }
    }

    Write-Host "`n⚠️ UYARI: Soket 10 saniyeden sonra hala açık kaldı!" -ForegroundColor Red
} catch {
    Write-Host "Sunucuya bağlanılamadı: $_" -ForegroundColor Red
} finally {
    if ($client) { $client.Close() }
}

