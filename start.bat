@echo off
setlocal

if exist .env (
  for /f "usebackq eol=# tokens=1,* delims==" %%A in (".env") do (
    if not "%%A"=="" set "%%A=%%B"
  )
)

if "%APP_HOST%"=="" set "APP_HOST=127.0.0.1"
if "%APP_PORT%"=="" set "APP_PORT=5000"
if "%DATABASE_URL%"=="" set "DATABASE_URL=sqlite:///proxy_manager.db"

python main.py
