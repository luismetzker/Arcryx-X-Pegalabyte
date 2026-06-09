<<<<<<< HEAD
@echo off
cls

echo ==========================
echo Enviando para o GitHub...
echo ==========================

cd /d "%~dp0"

git init

git add .

git commit -m "update site"

git branch -M main

git remote remove origin 2>nul
git remote add origin https://github.com/luismetzker/Arcryx-X-Pegalabyte

git pull origin main --allow-unrelated-histories

git push -u origin main

echo ==========================
echo Upload concluido!
echo ==========================

pause
=======
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
>>>>>>> 7f5987c92d304de67c2cae72ea8d005930b359e5
