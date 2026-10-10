@echo off
chcp 65001 >nul
title PS5 Relapse All-in-One Host
cd /d "%~dp0"

echo ==================================================
echo   PS5 Relapse All-in-One Host
echo --------------------------------------------------
echo   1. PS5 与本机连同一个路由器
echo   2. PS5 浏览器打开下方显示的地址
echo   3. 页面会自动完成破解并加载全部 payload
echo   4. 破解期间请不要关闭本窗口或让电脑休眠
echo ==================================================
echo.

where python >nul 2>nul
if %errorlevel%==0 (
    python serve.py
) else (
    where py >nul 2>nul
    if %errorlevel%==0 (
        py -3 serve.py
    ) else (
        echo [!] 未找到 Python，请先安装：https://www.python.org/downloads/
        echo     安装时勾选 "Add python.exe to PATH"
    )
)
pause
