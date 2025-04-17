@echo off
echo ===================================================
echo =     UniFortress - Монтирование USB диска        =
echo ===================================================
echo.
echo ВНИМАНИЕ! Этот скрипт нужно запускать от имени администратора!
echo.

REM Проверяем, передан ли номер диска
if "%1"=="" (
    echo Запуск без параметров. Будет показан список дисков.
    echo ---------------------------------------------------
    .\target\release\unifortress.exe list-devices
    echo ---------------------------------------------------
    
    set /p DISK_NUMBER=Введите номер диска для монтирования: 
) else (
    set DISK_NUMBER=%1
)

set MOUNT_POINT=M:\

echo.
echo ВНИМАНИЕ: Будет смонтирован диск №%DISK_NUMBER%
echo Диск будет смонтирован как %MOUNT_POINT%
echo.

set /p confirm=Продолжить монтирование? (y/n): 

if /i "%confirm%" NEQ "y" (
    echo Операция отменена.
    pause
    exit /b
)

set /p PASSWORD=Введите пароль для диска: 

echo.
echo Запускаем монтирование диска:
echo ---------------------------------------------------
.\target\release\unifortress.exe mount --device %DISK_NUMBER% --password %PASSWORD% --mount_point %MOUNT_POINT%
echo ---------------------------------------------------
echo.

echo Монтирование завершено.
pause 