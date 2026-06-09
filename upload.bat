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
git remote add origin https://github.com/SEU_USUARIO/SEU_REPOSITORIO.git

git pull origin main --allow-unrelated-histories

git push -u origin main

echo ==========================
echo Upload concluido!
echo ==========================

pause