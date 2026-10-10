@echo off
REM Build KeyBridge Windows client.
REM Requires MinGW (gcc) or MSVC (cl). Tries gcc first.

where gcc >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo Building with MinGW gcc...
    gcc -O2 -o keybridge.exe keybridge.c -lws2_32 -mwindows
    echo Done: keybridge.exe
    goto :eof
)

where cl >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo Building with MSVC cl...
    cl /O2 /W3 /D_CRT_SECURE_NO_WARNINGS /D_WINSOCK_DEPRECATED_NO_WARNINGS keybridge.c ws2_32.lib user32.lib shell32.lib gdi32.lib /link /SUBSYSTEM:WINDOWS /OUT:keybridge.exe
    echo Done: keybridge.exe
    goto :eof
)

echo ERROR: No compiler found. Install MinGW or Visual Studio.
exit /b 1
