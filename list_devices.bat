@echo off
echo ===================================================
echo =       UniFortress - Список доступных дисков     =
echo ===================================================
echo.
echo ВНИМАНИЕ! Этот скрипт запускает команду от имени администратора.
echo.
echo Будет выведен список доступных дисков для шифрования.
echo.
pause

echo.
echo Запускаем команду:
echo ---------------------------------------------------
powershell -Command "Start-Process -Verb RunAs '.\target\release\unifortress.exe' -ArgumentList 'list-devices'"
echo ---------------------------------------------------
echo.

echo Команда запущена. Результат будет показан в новом окне.
pause 