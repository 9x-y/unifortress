@echo off
echo ===================================================
echo =        UniFortress - Шифрование USB диска       =
echo ===================================================
echo.
echo ВНИМАНИЕ! Этот скрипт нужно запускать от имени администратора!
echo.
echo Будет зашифрован диск \\.\PhysicalDrive1 
echo (Обычно соответствует вашей подключенной USB флешке)
echo.
echo ВСЕ ДАННЫЕ НА ДИСКЕ БУДУТ УНИЧТОЖЕНЫ!
echo.
echo Перед шифрованием рекомендуется:
echo   1. Убедиться, что все данные с флешки сохранены
echo   2. Извлечь флешку и подключить ее заново
echo   3. Закрыть все программы, которые могут обращаться к флешке
echo.
pause

echo.
echo Перед началом шифрования показываем доступные диски:
echo ---------------------------------------------------
.\target\release\unifortress.exe list
echo ---------------------------------------------------
echo.
echo Запускаем шифрование диска:
echo ---------------------------------------------------
.\target\release\unifortress.exe encrypt --device "\\.\PhysicalDrive1"
echo ---------------------------------------------------
echo.

echo Операция завершена.
pause 