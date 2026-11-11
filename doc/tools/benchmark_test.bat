@echo off
chcp 65001 >nul
title ZMax Server - HTTP Yük ve Performans Testi
echo ============================================================
echo   ⚡ ZMax Server v0.1.0 - Bombardier HTTP Yük Testi
echo ============================================================
echo Hedef: http://127.0.0.1:19480/index.html
echo Eşzamanlı Bağlantı: 125
echo Test Süresi: 10 saniye
echo ============================================================
"%~dp0bombardier.exe" -c 125 -d 10s http://127.0.0.1:19480/index.html
echo ============================================================
pause

