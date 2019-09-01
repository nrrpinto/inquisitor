@ECHO OFF
FOR /F %%I IN ("%0") DO SET BATDIR=%%~dpI
powershell.exe -executionpolicy remotesigned -File %BATDIR%/inquisitor.ps1 -GUI
ECHO.
ECHO Hope you have enjoyed inquiring your system !!!
ECHO.
PAUSE


