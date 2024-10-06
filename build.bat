@echo off
pyinstaller --onedir ^
    --add-data "src/token.json;." ^
    --add-data "src/credentials.csv;." ^
    --add-data "src/client_secret.json;." ^
    --add-data "src/driver/msedgedriver.exe;driver" ^
    --add-data "src/assets/logo.png;assets" ^
    src/main.py
pause
