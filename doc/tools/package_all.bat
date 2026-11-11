@echo off
chcp 65001 >nul
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0\..\.."

set "MODE=full"
set "SKIP_BUILD=0"
set "NO_PAUSE=0"

:parse_args
if "%~1"=="" goto args_done
if /I "%~1"=="win" set "MODE=win"
if /I "%~1"=="--win" set "MODE=win"
if /I "%~1"=="--win-only" set "MODE=win"
if /I "%~1"=="full" set "MODE=full"
if /I "%~1"=="--full" set "MODE=full"
if /I "%~1"=="--skip-build" set "SKIP_BUILD=1"
if /I "%~1"=="--nopause" set "NO_PAUSE=1"
if /I "%~1"=="--no-pause" set "NO_PAUSE=1"
if /I "%~1"=="-h" goto show_help
if /I "%~1"=="--help" goto show_help
shift
goto parse_args

:show_help
echo Kullanim: package_all.bat [full ^| win] [--skip-build] [--nopause]
echo   full         : Windows + kurulu Linux musl x64/arm64 hedeflerini derler ve tum paketleri uretir
echo   win          : Yalnizca Windows x64 derlemesi ve .zip paketi uretir
echo   --skip-build : Cargo derleme adimlarini atlayip mevcut ikili dosyalarla paketler
echo   --nopause    : Bitis ekraninda bekleme yapmadan cikar
exit /b 0

:args_done
echo ============================================================
echo   ZMax Server v1.0.01 - Kurumsal Paket Uretici
echo   Mod: %MODE% ^| Derleme Atla: %SKIP_BUILD%
echo ============================================================

rem Oturum PATH iyilestirmesi (WinGet zig ve yerel Python yollari)
if exist "%LOCALAPPDATA%\Microsoft\WinGet\Links\zig.exe" (
    where zig >nul 2>&1 || set "PATH=%LOCALAPPDATA%\Microsoft\WinGet\Links;%PATH%"
)
if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" (
    where python >nul 2>&1 || set "PATH=%LOCALAPPDATA%\Programs\Python\Python313;%LOCALAPPDATA%\Programs\Python\Python313\Scripts;%PATH%"
)
if exist "%LOCALAPPDATA%\Programs\Python\Python314\python.exe" (
    where python >nul 2>&1 || set "PATH=%LOCALAPPDATA%\Programs\Python\Python314;%LOCALAPPDATA%\Programs\Python\Python314\Scripts;%PATH%"
)

set "PYTHON_EXE="
where python >nul 2>&1 && for /f "delims=" %%P in ('where python 2^>nul') do if not defined PYTHON_EXE set "PYTHON_EXE=%%P"

set "HAS_ZIG=0"
where zig >nul 2>&1 && set "HAS_ZIG=1"

if "%SKIP_BUILD%"=="1" goto step_package

echo.
echo [1/4] Windows Release derlemesi yapiliyor...
cargo build --release
if not "%ERRORLEVEL%"=="0" (
    echo [HATA] Windows Release derlemesi basarisiz oldu!
    goto fail_exit
)

if /I "%MODE%"=="win" goto step_package

echo.
echo [2/4] Linux musl capraz derleme hedefleri kontrol ediliyor...
if "%HAS_ZIG%"=="0" (
    echo [BILGI] zig bulunamadi; Linux musl capraz derleme adimlari atlandi.
    goto step_package
)
if not defined PYTHON_EXE (
    echo [BILGI] python bulunamadi; zig-cc sarmalayicilari icin python gerektiginden Linux derlemeleri atlandi.
    goto step_package
)

set "HAS_X64_MUSL=0"
set "HAS_ARM64_MUSL=0"
for /f "delims=" %%T in ('rustup target list --installed 2^>nul') do (
    if "%%T"=="x86_64-unknown-linux-musl" set "HAS_X64_MUSL=1"
    if "%%T"=="aarch64-unknown-linux-musl" set "HAS_ARM64_MUSL=1"
)

if "%HAS_X64_MUSL%"=="1" (
    echo [2a/4] Linux x64 musl Release derlemesi yapiliyor...
    cargo build --release --target x86_64-unknown-linux-musl
    if not "!ERRORLEVEL!"=="0" (
        echo [HATA] x86_64-unknown-linux-musl derlemesi basarisiz oldu!
        goto fail_exit
    )
) else (
    echo [BILGI] x86_64-unknown-linux-musl hedefi kurulu degil; atlandi.
)

if "%HAS_ARM64_MUSL%"=="1" (
    echo [2b/4] Linux ARM64 musl Release derlemesi yapiliyor...
    cargo build --release --target aarch64-unknown-linux-musl
    if not "!ERRORLEVEL!"=="0" (
        echo [HATA] aarch64-unknown-linux-musl derlemesi basarisiz oldu!
        goto fail_exit
    )
) else (
    echo [BILGI] aarch64-unknown-linux-musl hedefi kurulu degil; atlandi.
)

:step_package
echo.
if defined PYTHON_EXE goto package_with_python
goto package_fallback_win

:package_with_python
echo [3/4] Python paketleyici calistiriliyor (doc\tools\pack_zmax.py)...
if /I "%MODE%"=="win" (
    "%PYTHON_EXE%" "doc\tools\pack_zmax.py" --target win
) else (
    "%PYTHON_EXE%" "doc\tools\pack_zmax.py" --target all
)
if not "%ERRORLEVEL%"=="0" (
    echo [HATA] Paket uretimi basarisiz oldu!
    goto fail_exit
)

echo.
echo [4/4] Uretilen paketler dogrulaniyor (doc\tools\verify_packages.py)...
"%PYTHON_EXE%" "doc\tools\verify_packages.py" --allow-missing
if not "%ERRORLEVEL%"=="0" (
    echo [HATA] Paket dogrulama basarisiz oldu!
    goto fail_exit
)
goto success_exit

:package_fallback_win
echo [3/4] Python bulunamadigi icin klasik Windows paketleme akisi kullaniliyor...
if not exist "packed\win\bin" mkdir "packed\win\bin"
if not exist "packed\win\logs" mkdir "packed\win\logs"
if not exist "packed\win\cachedata" mkdir "packed\win\cachedata"
copy /Y "target\release\zmax.exe" "bin\zmax.exe" >nul
copy /Y "target\release\zmax.exe" "packed\win\bin\zmax.exe" >nul
if exist "bin\zmaxctrl.bat" copy /Y "bin\zmaxctrl.bat" "packed\win\bin\zmaxctrl.bat" >nul
xcopy /E /I /Y "conf" "packed\win\conf" >nul
xcopy /E /I /Y "admin" "packed\win\admin" >nul
xcopy /E /I /Y "modules" "packed\win\modules" >nul
xcopy /E /I /Y "fcgi-bin" "packed\win\fcgi-bin" >nul
xcopy /E /I /Y "www" "packed\win\www" >nul
powershell -Command "Compress-Archive -Path 'packed\win' -DestinationPath 'packed\zmax-server-v1.0.01-windows-x64.zip' -Force"
if not "%ERRORLEVEL%"=="0" (
    echo [HATA] Windows ZIP arsivi olusturulamadi!
    goto fail_exit
)

:success_exit
echo.
echo ============================================================
echo [OK] Tum paketleme islemleri basariyla tamamlandi!
echo Konum: %CD%\packed\
echo ============================================================
if "%NO_PAUSE%"=="0" pause
exit /b 0

:fail_exit
if "%NO_PAUSE%"=="0" pause
exit /b 1
