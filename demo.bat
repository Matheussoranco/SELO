@echo off
rem Demo do SELO: cria o ambiente virtual na primeira vez e roda os cenarios narrados.
rem Uso: duplo clique, ou  demo.bat [--lang en]
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
    echo Criando ambiente virtual e instalando dependencias...
    python -m venv .venv || goto :erro
    .venv\Scripts\python -m pip install -q -e . || goto :erro
)
.venv\Scripts\python -m cripto_agent demo %*
echo.
pause
exit /b 0
:erro
echo Falhou. Requisitos: Python 3.11+ no PATH e acesso a internet na primeira execucao.
pause
exit /b 1
