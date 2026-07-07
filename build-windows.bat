@echo off
setlocal EnableExtensions EnableDelayedExpansion

for %%I in ("%~dp0.") do set "ROOT=%%~fI"
set "BUILD_DIR=%ROOT%\build-windows"
set "OUTPUT_DIR=%ROOT%\output\windows"
set "OPENSSL_SHIM=%BUILD_DIR%-openssl-root"

if /i "%~1"=="clean" (
    echo [clean] removing build and output directories
    if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
    if exist "%OPENSSL_SHIM%" rmdir /s /q "%OPENSSL_SHIM%"
    if exist "%OUTPUT_DIR%" rmdir /s /q "%OUTPUT_DIR%"
    exit /b 0
)

call :find_cmake || exit /b 1
call :find_ninja || exit /b 1
call :find_mingw || exit /b 1
call :find_openssl || exit /b 1
call :make_openssl_shim || exit /b 1

echo.
echo [config] CMake:  "%CMAKE_EXE%"
echo [config] Ninja:  "%NINJA_EXE%"
echo [config] C:      "%CC_EXE%"
echo [config] CXX:    "%CXX_EXE%"
echo [config] OpenSSL "%OPENSSL_ROOT%"
echo.

"%CMAKE_EXE%" ^
    -B "%BUILD_DIR%" ^
    -G Ninja ^
    -DCMAKE_MAKE_PROGRAM="%NINJA_EXE%" ^
    -DCMAKE_C_COMPILER="%CC_EXE%" ^
    -DCMAKE_CXX_COMPILER="%CXX_EXE%" ^
    -DOPENSSL_ROOT_DIR="%OPENSSL_ROOT%" ^
    -DOPENSSL_INCLUDE_DIR="%OPENSSL_SHIM%\include" ^
    -DOPENSSL_SSL_LIBRARY="%SSL_LIB%" ^
    -DOPENSSL_CRYPTO_LIBRARY="%CRYPTO_LIB%" ^
    -DCANDY_STATIC_SPDLOG=ON ^
    -DCANDY_STATIC_POCO=ON ^
    -DCMAKE_BUILD_TYPE=RelWithDebInfo ^
    "%ROOT%"
if errorlevel 1 exit /b 1

"%CMAKE_EXE%" --build "%BUILD_DIR%"
if errorlevel 1 exit /b 1

if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"
copy /y "%BUILD_DIR%\candy-cli\candy.exe" "%OUTPUT_DIR%\" >nul
copy /y "%BUILD_DIR%\candy-service\candy-service.exe" "%OUTPUT_DIR%\" >nul
if exist "%ROOT%\candy.cfg" copy /y "%ROOT%\candy.cfg" "%OUTPUT_DIR%\" >nul
call :copy_wintun

echo.
echo [done] output:
echo        %OUTPUT_DIR%\candy.exe
echo        %OUTPUT_DIR%\candy-service.exe
echo.
if /i not "%~1"=="nopause" pause
exit /b 0

:find_cmake
if defined CMAKE_EXE if exist "%CMAKE_EXE%" exit /b 0
for /f "delims=" %%F in ('where cmake 2^>nul') do (
    set "CMAKE_EXE=%%F"
    exit /b 0
)
for /f "delims=" %%F in ('powershell -NoProfile -ExecutionPolicy Bypass -Command "$roots=@('C:\Program Files\Microsoft Visual Studio','C:\Program Files (x86)\Microsoft Visual Studio') | ? { Test-Path $_ }; $p=Get-ChildItem $roots -Recurse -Filter cmake.exe -ErrorAction SilentlyContinue | ? { $_.FullName -like '*CommonExtensions*Microsoft*CMake*CMake*bin*' } | Select-Object -First 1 -ExpandProperty FullName; if($p){$p}" 2^>nul') do (
    set "CMAKE_EXE=%%F"
    exit /b 0
)
echo [error] cmake.exe not found. Install CMake or Visual Studio CMake tools.
exit /b 1

:find_ninja
if defined NINJA_EXE if exist "%NINJA_EXE%" exit /b 0
for /f "delims=" %%F in ('where ninja 2^>nul') do (
    set "NINJA_EXE=%%F"
    exit /b 0
)
for /f "delims=" %%F in ('powershell -NoProfile -ExecutionPolicy Bypass -Command "$roots=@('C:\Program Files\Microsoft Visual Studio','C:\Program Files (x86)\Microsoft Visual Studio') | ? { Test-Path $_ }; $p=Get-ChildItem $roots -Recurse -Filter ninja.exe -ErrorAction SilentlyContinue | ? { $_.FullName -like '*CommonExtensions*Microsoft*CMake*Ninja*' } | Select-Object -First 1 -ExpandProperty FullName; if($p){$p}" 2^>nul') do (
    set "NINJA_EXE=%%F"
    exit /b 0
)
echo [error] ninja.exe not found. Install Ninja or Visual Studio CMake tools.
exit /b 1

:find_mingw
if defined CC if exist "%CC%" set "CC_EXE=%CC%"
if defined CXX if exist "%CXX%" set "CXX_EXE=%CXX%"
if defined CC_EXE if defined CXX_EXE goto mingw_prefix
for /f "delims=" %%F in ('where gcc 2^>nul') do (
    set "CC_EXE=%%F"
    goto find_gxx
)
for %%D in ("D:\msys64\mingw64\bin" "C:\msys64\mingw64\bin") do (
    if exist "%%~D\gcc.exe" (
        set "CC_EXE=%%~D\gcc.exe"
        goto find_gxx
    )
)
:find_gxx
for /f "delims=" %%F in ('where g++ 2^>nul') do (
    set "CXX_EXE=%%F"
    goto mingw_prefix
)
for %%D in ("D:\msys64\mingw64\bin" "C:\msys64\mingw64\bin") do (
    if exist "%%~D\g++.exe" (
        set "CXX_EXE=%%~D\g++.exe"
        goto mingw_prefix
    )
)
:mingw_prefix
if not defined CC_EXE (
    echo [error] gcc.exe not found. Install MSYS2 MinGW64 toolchain.
    exit /b 1
)
if not defined CXX_EXE (
    echo [error] g++.exe not found. Install MSYS2 MinGW64 toolchain.
    exit /b 1
)
for %%I in ("%CC_EXE%") do for %%J in ("%%~dpI..") do set "MINGW_PREFIX=%%~fJ"
exit /b 0

:find_openssl
if defined OPENSSL_ROOT_DIR (
    set "OPENSSL_ROOT=%OPENSSL_ROOT_DIR%"
) else (
    set "OPENSSL_ROOT=%MINGW_PREFIX%"
)
if not exist "%OPENSSL_ROOT%\include\openssl\ssl.h" (
    echo [error] OpenSSL headers not found under "%OPENSSL_ROOT%".
    echo         Set OPENSSL_ROOT_DIR to a MinGW OpenSSL prefix and run again.
    exit /b 1
)
if exist "%OPENSSL_ROOT%\lib\libssl.dll.a" (
    set "SSL_LIB=%OPENSSL_ROOT%\lib\libssl.dll.a"
) else if exist "%OPENSSL_ROOT%\lib\libssl.a" (
    set "SSL_LIB=%OPENSSL_ROOT%\lib\libssl.a"
) else (
    echo [error] libssl not found under "%OPENSSL_ROOT%\lib".
    exit /b 1
)
if exist "%OPENSSL_ROOT%\lib\libcrypto.dll.a" (
    set "CRYPTO_LIB=%OPENSSL_ROOT%\lib\libcrypto.dll.a"
) else if exist "%OPENSSL_ROOT%\lib\libcrypto.a" (
    set "CRYPTO_LIB=%OPENSSL_ROOT%\lib\libcrypto.a"
) else (
    echo [error] libcrypto not found under "%OPENSSL_ROOT%\lib".
    exit /b 1
)
exit /b 0

:make_openssl_shim
if not exist "%OPENSSL_SHIM%\include" mkdir "%OPENSSL_SHIM%\include"
if exist "%OPENSSL_SHIM%\include\openssl" rmdir "%OPENSSL_SHIM%\include\openssl"
mklink /J "%OPENSSL_SHIM%\include\openssl" "%OPENSSL_ROOT%\include\openssl" >nul
if errorlevel 1 (
    echo [error] failed to create OpenSSL include junction.
    exit /b 1
)
exit /b 0

:copy_wintun
set "WINTUN_ARCH=amd64"
if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "WINTUN_ARCH=arm64"
if /i "%PROCESSOR_ARCHITECTURE%"=="x86" set "WINTUN_ARCH=x86"
if exist "%BUILD_DIR%\candy\wintun\bin\%WINTUN_ARCH%\wintun.dll" (
    copy /y "%BUILD_DIR%\candy\wintun\bin\%WINTUN_ARCH%\wintun.dll" "%OUTPUT_DIR%\" >nul
)
exit /b 0
