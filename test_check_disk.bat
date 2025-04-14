@echo off
echo ===================================================
echo =          UniFortress - Проверка USB диска       =
echo ===================================================
echo.
echo ВНИМАНИЕ! Этот скрипт нужно запускать от имени администратора!
echo.
echo Будет выполнена проверка диска \\.\PhysicalDrive1
echo (Обычно соответствует вашей подключенной USB флешке)
echo.
echo Если вы видите ошибку доступа, убедитесь, что:
echo   1. Вы запустили скрипт от имени администратора
echo   2. Флешка подключена к компьютеру
echo   3. Флешка была предварительно зашифрована
echo.
pause

echo.
echo Запускаем проверку диска:
echo ---------------------------------------------------
.\target\release\unifortress.exe check --device "\\.\PhysicalDrive1"
echo ---------------------------------------------------
echo.

echo Проверка завершена.
pause 