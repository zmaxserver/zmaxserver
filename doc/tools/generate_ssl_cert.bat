@echo off
chcp 65001 >nul
echo ============================================================
echo   ⚡ ZMax Server - Geliştirici SSL Sertifikası Üretici
echo ============================================================
powershell -Command "$cert = New-SelfSignedCertificate -DnsName 'localhost', '127.0.0.1' -CertStoreLocation 'cert:\LocalMachine\My'; Export-Certificate -Cert $cert -FilePath '%~dp0..\..\conf\ssl_localhost.cer'; Write-Host '[OK] Kendinden imzali sertifika olusturuldu.'"
echo ============================================================
pause

