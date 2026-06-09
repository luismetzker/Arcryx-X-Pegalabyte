@echo off
cls

echo ==========================
echo  UPLOAD PARA GITHUB
echo ==========================
git rm -r --cached node_modules
cd /d "%~dp0"

:: evita problema de repo quebrado
if not exist ".git" (
    git init
)

:: adiciona tudo do projeto (SÓ essa pasta)
git add .

:: commit automático com data/hora
git commit -m "update %date% %time%"

:: garante branch main
git branch -M main

:: configura remote (remove e recria pra não dar erro)
git remote remove origin 2>nul
git remote add origin https://github.com/luismetzker/Arcryx-X-Pegalabyte.git

:: garante sincronização com repo remoto
git pull origin main --allow-unrelated-histories 2>nul

:: envia tudo
git push -u origin main

echo ==========================
echo  UPLOAD FINALIZADO
echo ==========================
pause