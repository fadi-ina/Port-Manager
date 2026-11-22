@echo off
rem Double-click this file to open Port Manager (Windows will ask for Administrator permission)
start "" powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0PortManager.ps1"
