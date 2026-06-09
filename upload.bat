```bat
@echo off
title Arcryx GitHub Upload

REM Vai para a pasta onde o .bat está
cd /d "%~dp0"

echo ==========================
echo Projeto:
echo %CD%
echo ==========================
echo.

git init

git branch -M main

git add .

git commit -m "Atualizacao %date% %time%"

git remote remove origin 2>nul

git remote add origin https://github.com/luismetzker/Arcryx-X-Pegalabyte.git

git push -u origin main

echo.
echo ==========================
echo Processo concluido
echo ==========================
pause
```
