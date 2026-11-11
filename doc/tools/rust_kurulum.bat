@echo off
chcp 65001 >nul
echo ====================================================
echo ZMax Server - Rust Gelistirici Ortami Kurulumu
echo ====================================================
echo.
echo Rust ve Cargo araclari otomatik kuruluyor, lutfen bekleyin...
echo.

cd /d "%~dp0"
rustup-init.exe -y

echo.
echo ====================================================
echo Kurulum tamamlandi!
echo Terminali yeniden baslatarak "cargo --version" ile dogrulayabilirsiniz.
echo ====================================================
pause

